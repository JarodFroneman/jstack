#!/usr/bin/env python3
"""Local stdio MCP server for controlled gstack workflow access.

This server intentionally avoids arbitrary shell execution. Tools expose
project detection, skill discovery, review/QA planning, lightweight health
checks, security scanning, and context save/restore.
"""

from __future__ import annotations

import datetime as _dt
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Optional


_SERVER_DIR = Path(__file__).resolve().parent
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))
import audit as audit_core
import authorization as authorization_core
import capabilities as capability_core
import launch as launch_core
import loop as loop_core
import program as program_core


SERVER_NAME = "jstack-mcp"
SERVER_VERSION = "0.8.0"
PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
MAX_OUTPUT_CHARS = 12_000
MAX_CHANGED_FILES = 10_000
MAX_FINGERPRINT_BYTES = 512_000_000
MAX_FINGERPRINT_FILES = 100_000
AUDIT_MAX_STRUCTURED_INPUT_BYTES = 2_000_000
AUDIT_MAX_STRUCTURED_OUTPUT_BYTES = 5_000_000
RECEIPT_MAX_AGE_SECONDS = 24 * 60 * 60
GOAL_READINESS_RECEIPT_MAX_AGE_SECONDS = 30 * 60
LOOP_MAX_QA_RECEIPTS = 50
LOOP_MAX_AUDIT_RECEIPTS = 20
LOOP_MAX_RECEIPT_CHARS = 100_000
SPECIALIST_MAX_RECEIPTS = 20
SPECIALIST_MAX_RECEIPT_CHARS = 200_000
SPECIALIST_MAX_STRUCTURED_BYTES = 100_000
SPECIALIST_MAX_HANDOFF_BYTES = 2_500_000
PROGRAM_MAX_RECEIPT_CHARS = 100_000
PROGRAM_MAX_ARTIFACT_BYTES = 100_000_000
PROGRAM_ARTIFACT_TIMEOUT_SECONDS = 30
LAUNCH_MAX_RECEIPTS = 100
LAUNCH_MAX_RECEIPT_CHARS = 100_000
LAUNCH_MAX_ARTIFACT_BYTES = 100_000_000
LAUNCH_ARTIFACT_TIMEOUT_SECONDS = 30
LAUNCH_SESSION_MAX_AGE_SECONDS = 30 * 60
LAUNCH_RECEIPT_MAX_AGE_SECONDS = 24 * 60 * 60
PROGRAM_IDENTITY_CONFIG_ENV = "JSTACK_PROGRAM_IDENTITY_CONFIG"
PROGRAM_IDENTITY_CONFIG_SCHEMA = "jstack.program.identity-config.v1"
EXTERNAL_ACTION_IDENTITY_CONFIG_ENV = "JSTACK_EXTERNAL_ACTION_IDENTITY_CONFIG"
EXTERNAL_ACTION_IDENTITY_CONFIG_SCHEMA = "jstack.external-action.identity-config.v1"
EXTERNAL_ACTION_MAX_RECEIPT_CHARS = 100_000
EXTERNAL_ACTION_PERMIT_MAX_AGE_SECONDS = 60
AUDIT_CAPSTONE_ATTESTATION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
AUDIT_CAPSTONE_ATTESTATION_SCHEMA = "jstack.audit.capstone-attestation.v1"
AUDIT_CAPSTONE_ASSESSOR_KEY_ENV = "JSTACK_AUDIT_ASSESSOR_HMAC_KEY"
LOOP_CAPSTONE_ATTESTATION_SCHEMA = "jstack.loop.capstone-attestation.v1"
LOOP_CAPSTONE_ASSESSOR_KEY_ENV = "JSTACK_LOOP_ASSESSOR_HMAC_KEY"
SERVER_SESSION_ID = secrets.token_hex(16)
_RECEIPT_SECRET = secrets.token_bytes(32)
_MCP_INITIALIZED = False

GIT_REQUIRED_TOOLS = [
    "jstack_mastery_record",
    "jstack_policy_check",
    "jstack_preflight",
    "jstack_health",
    "jstack_review",
    "jstack_security_audit",
    "jstack_qa",
    "jstack_context_save",
    "jstack_context_restore",
    "jstack_ship_check",
    "jstack_release_readiness",
    "jstack_launch_assess",
    "jstack_launch_evidence_register",
    "jstack_launch_finalize",
    "jstack_quant_backtest_review",
    "jstack_specialist_result",
    "jstack_specialist_handoff_check",
    "jstack_loop_goal_readiness",
    "jstack_loop_start",
    "jstack_loop_status",
    "jstack_loop_checkpoint",
    "jstack_loop_revise",
    "jstack_loop_stop",
    "jstack_loop_finalize",
    "jstack_program_goal_readiness",
    "jstack_program_start",
    "jstack_program_status",
    "jstack_program_next",
    "jstack_program_phase_bind",
    "jstack_program_phase_complete",
    "jstack_program_gate_challenge",
    "jstack_program_gate_resolve",
    "jstack_program_evidence_register",
    "jstack_program_pause",
    "jstack_program_resume",
    "jstack_program_revise",
    "jstack_program_cancel",
    "jstack_program_finalize",
    "jstack_external_action_challenge",
    "jstack_external_action_authorize",
    "jstack_external_action_consume",
]
ARTIFACT_ONLY_RELEASE_BLOCKER = (
    "Git-backed JStack release readiness is unavailable until the authoritative source has a committed git repository."
)
ARTIFACT_EVIDENCE_REQUIREMENTS = [
    "Hash every release input and deployed artifact with SHA-256 and record the path-to-hash mapping.",
    "Record the exact build and test commands, exit statuses, timestamps, and bounded output.",
    "Create and verify a timestamped pre-change backup before mutating the target environment.",
    "Record the deployed container image digest, package version, or equivalent immutable runtime identity.",
    "Document staged dependency order, approval, rollback steps, and rollback verification.",
    "Run authenticated internal checks and independent public smoke checks against the released surface.",
    "Capture post-release monitoring evidence and unresolved risks in the handoff.",
]

EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "__pycache__",
}


class ToolError(Exception):
    """Expected tool error with an actionable message."""


class InputError(ToolError):
    """Invalid JSON-RPC or tool input."""


def validate_schema_value(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    expected = schema.get("type")
    valid = True
    if expected == "object":
        valid = isinstance(value, dict)
    elif expected == "array":
        valid = isinstance(value, list)
    elif expected == "string":
        valid = isinstance(value, str)
    elif expected == "boolean":
        valid = isinstance(value, bool)
    elif expected == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif expected == "number":
        valid = isinstance(value, (int, float)) and not isinstance(value, bool)
    if not valid:
        raise InputError(f"{path} must be of type {expected}.")
    if "enum" in schema and value not in schema["enum"]:
        raise InputError(f"{path} must be one of: {schema['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise InputError(f"{path} must be at least {schema['minimum']}.")
        if "maximum" in schema and value > schema["maximum"]:
            raise InputError(f"{path} must be at most {schema['maximum']}.")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise InputError(f"{path} must contain at least {schema['minLength']} characters.")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise InputError(f"{path} must contain at most {schema['maxLength']} characters.")
    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                raise InputError(f"{path}.{field} is required.")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise InputError(f"{path} contains unsupported fields: {', '.join(unknown)}")
        for field, child in value.items():
            if field in properties:
                validate_schema_value(child, properties[field], f"{path}.{field}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise InputError(f"{path} must contain at least {schema['minItems']} items.")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise InputError(f"{path} must contain at most {schema['maxItems']} items.")
        for index, child in enumerate(value):
            validate_schema_value(child, schema["items"], f"{path}[{index}]")


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def truncate(value: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n... truncated {len(value) - limit} chars"


def json_text(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def expand_path(path: Optional[str]) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    return Path.cwd().resolve()


def require_directory_path(path: Optional[str] = None) -> Path:
    project_path = expand_path(path)
    if not project_path.exists():
        raise ToolError(f"Project path does not exist: {project_path}")
    if not project_path.is_dir():
        raise ToolError(f"Project path must be a directory: {project_path}")
    return project_path


def require_project_path(path: Optional[str] = None) -> Path:
    project_path = require_directory_path(path)
    root = git_root(project_path)
    if not root:
        raise ToolError(f"JStack Git-backed evidence tools require a git repository: {project_path}")
    return Path(root).resolve()


def decode_git_relative_path(raw: bytes, label: str) -> str:
    try:
        relative = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ToolError(f"Git returned a {label} path that is not valid UTF-8.") from exc
    if "\\" in relative or any(
        ord(character) < 32 or ord(character) == 127 for character in relative
    ):
        raise ToolError(
            f"Git returned a {label} path containing a literal backslash or control character; evidence cannot represent it safely."
        )
    parts = relative.split("/")
    if (
        not relative
        or relative.startswith("/")
        or any(part in {"", ".", ".."} or part.lower() == ".git" for part in parts)
    ):
        raise ToolError(f"Git returned an unsafe {label} repository path.")
    return relative


def resolve_project_binding(path: Optional[str] = None) -> dict[str, Any]:
    requested_path = require_directory_path(path)
    root = git_root(requested_path)
    if root:
        project_path = Path(root).resolve()
        return {
            "mode": "git",
            "evidenceMode": "git",
            "requestedPath": str(requested_path),
            "projectPath": str(project_path),
            "gitRoot": str(project_path),
            "gitEvidenceAvailable": True,
            "gitEvidenceToolsAvailable": True,
            "releaseReadinessToolAvailable": True,
            "gitRequiredTools": GIT_REQUIRED_TOOLS,
            "blockedTools": [],
            "limitations": [],
            "diagnostic": "MCP mounted; project binding is git-backed.",
        }
    return {
        "mode": "artifact-only",
        "evidenceMode": "artifact-only",
        "requestedPath": str(requested_path),
        "projectPath": str(requested_path),
        "gitRoot": None,
        "gitEvidenceAvailable": False,
        "gitEvidenceToolsAvailable": False,
        "releaseReadinessToolAvailable": False,
        "gitRequiredTools": GIT_REQUIRED_TOOLS,
        "blockedTools": GIT_REQUIRED_TOOLS,
        "limitations": [
            "Commit-bound QA and security receipts cannot be issued.",
            "Git delta, protected-path, policy, context, and release-readiness gates are unavailable.",
            "Direct artifact evidence is supplemental and cannot be represented as JStack release certification.",
        ],
        "diagnostic": "MCP mounted; project binding is artifact-only because no valid git repository was found.",
    }


def trusted_git_line_ending_overrides(executable: str, cwd: Path, env: dict[str, str]) -> list[str]:
    allowed_values = {
        "core.autocrlf": {
            "true": "true",
            "yes": "true",
            "on": "true",
            "1": "true",
            "false": "false",
            "no": "false",
            "off": "false",
            "0": "false",
            "input": "input",
        },
        "core.eol": {"lf": "lf", "crlf": "crlf", "native": "native"},
    }
    overrides: list[str] = []
    for key, values in allowed_values.items():
        try:
            result = subprocess.run(
                [executable, "config", "--get", key],
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        value = result.stdout.decode("utf-8", errors="replace").strip().lower()
        normalized = values.get(value) if result.returncode == 0 else None
        if normalized:
            overrides.extend(["-c", f"{key}={normalized}"])
    return overrides


def process_environment(args: list[str], cwd: Path) -> tuple[list[str], Optional[dict[str, str]]]:
    if not args or args[0] != "git":
        return args, None
    candidates = [
        Path("/usr/bin/git"),
        Path("/usr/local/bin/git"),
        Path("/opt/homebrew/bin/git"),
        Path("C:/Program Files/Git/cmd/git.exe"),
        Path("C:/Program Files/Git/bin/git.exe"),
    ]
    discovered = shutil.which("git")
    if discovered:
        candidates.append(Path(discovered))
    executable: Optional[str] = None
    for candidate in candidates:
        if not candidate.exists() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        try:
            resolved.relative_to(cwd.resolve())
            continue
        except ValueError:
            executable = str(resolved)
            break
    if not executable:
        raise ToolError("No trusted git executable was found outside the project directory.")
    env = os.environ.copy()
    for name in (
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
    ):
        env.pop(name, None)
    line_ending_overrides = trusted_git_line_ending_overrides(executable, cwd, env)
    null_device = "NUL" if os.name == "nt" else "/dev/null"
    env.update(
        {
            "GIT_CONFIG_GLOBAL": null_device,
            "GIT_CONFIG_SYSTEM": null_device,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    hardened = [
        executable,
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={null_device}",
        "-c",
        "diff.external=",
        *line_ending_overrides,
        *args[1:],
    ]
    return hardened, env


def safe_run(args: list[str], cwd: Path, timeout: int = 20) -> dict[str, Any]:
    completed = run_complete(args, cwd, timeout=timeout, max_bytes=5_000_000)
    stdout = completed["stdout"].decode("utf-8", errors="replace")
    return {
        "ok": completed["ok"],
        "returncode": completed["returncode"],
        "stdout": truncate(stdout),
        "stderr": truncate(completed["stderr"]),
        "args": args,
    }


def run_complete(args: list[str], cwd: Path, timeout: int = 20, max_bytes: int = 5_000_000) -> dict[str, Any]:
    """Run a trusted read-only command without silently truncating its evidence."""
    process_args, env = process_environment(args, cwd)
    try:
        process = subprocess.Popen(
            process_args,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=(os.name != "nt"),
        )
    except FileNotFoundError:
        return {"ok": False, "returncode": 127, "stdout": b"", "stderr": f"Command not found: {args[0]}", "args": args}
    assert process.stdout and process.stderr
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = threading.Event()
    lock = threading.Lock()
    captured = [0]

    def read_stream(stream: Any, buffer: bytearray) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            with lock:
                remaining = max_bytes - captured[0]
                accepted = min(len(chunk), max(0, remaining))
                if accepted:
                    buffer.extend(chunk[:accepted])
                    captured[0] += accepted
                if accepted < len(chunk):
                    overflow.set()
                    return

    readers = [
        threading.Thread(target=read_stream, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=read_stream, args=(process.stderr, stderr_buffer), daemon=True),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            break
        time.sleep(0.01)
    process.wait(timeout=5)
    for reader in readers:
        reader.join(timeout=2)
    process.stdout.close()
    process.stderr.close()
    stderr = stderr_buffer.decode("utf-8", errors="replace")
    if timed_out:
        return {
            "ok": False,
            "returncode": 124,
            "stdout": bytes(stdout_buffer),
            "stderr": stderr + f"\nTimed out after {timeout}s; process group terminated.",
            "args": args,
        }
    if overflow.is_set():
        return {
            "ok": False,
            "returncode": 125,
            "stdout": bytes(stdout_buffer),
            "stderr": f"Command evidence exceeded the {max_bytes}-byte safety limit.",
            "args": args,
        }
    return {
        "ok": process.returncode == 0,
        "returncode": process.returncode,
        "stdout": bytes(stdout_buffer),
        "stderr": stderr,
        "args": args,
    }


def git_root(project_path: Path) -> Optional[str]:
    result = safe_run(["git", "rev-parse", "--show-toplevel"], project_path, timeout=8)
    if result["ok"] and result["stdout"].strip():
        return result["stdout"].strip()
    return None


def find_gstack_root() -> Optional[Path]:
    candidates = [
        os.environ.get("GSTACK_ROOT"),
        str(Path.home() / ".gstack" / "repos" / "gstack"),
        str(Path.home() / ".codex" / "skills" / "gstack"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate).expanduser().resolve()
        if (root / "SKILL.md").exists() or (root / "bin").exists():
            return root
    return None


def find_jstack_root() -> Optional[Path]:
    server_dir = Path(__file__).resolve().parent
    candidates = [
        os.environ.get("JSTACK_ROOT"),
        str(server_dir.parents[1]) if len(server_dir.parents) > 1 else None,
        str(server_dir.parent),
        str(Path.home() / ".codex" / "skills" / "jstack-dev"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate).expanduser().resolve()
        if (root / "skills" / "jstack-dev" / "SKILL.md").exists() or (root / "SKILL.md").exists():
            return root
    return None


def gstack_bin() -> Optional[Path]:
    root = find_gstack_root()
    if not root:
        return None
    candidate = root / "bin"
    return candidate if candidate.exists() else None


def project_slug(project_path: Path) -> str:
    digest = hashlib.sha256(str(project_path).encode("utf-8")).hexdigest()[:12]
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", project_path.name).strip("-") or "project"
    return f"{base}-{digest}"


def read_json(path: Path) -> Optional[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


DEFAULT_ENTERPRISE_POLICY: dict[str, Any] = {
    "schemaVersion": "jstack.enterprise.v1",
    "standard": "enterprise",
    "requiredChecks": [
        "project_instructions_read",
        "git_status_reviewed",
        "diff_check_clean",
        "test_commands_discovered",
        "focused_tests_run_or_blocked",
        "secret_scan_clean",
        "security_review_for_sensitive_work",
        "launch_assurance_for_production",
        "release_approval_for_production",
        "exact_external_action_authorization",
        "rollback_plan_for_production",
        "post_release_monitoring_for_production",
    ],
    "protectedPaths": [
        ".env",
        ".env.*",
        "**/.env",
        "**/.env.*",
        "secrets/**",
        "**/secrets/**",
        "config/production*",
        "**/production*",
        ".github/workflows/**",
        "infra/**",
        "migrations/**",
    ],
    "release": {
        "requiresExplicitApproval": True,
        "requiresRollbackPlan": True,
        "requiresCanaryOrMonitoring": True,
        "requiresCleanDiffCheck": True,
    },
    "externalActions": {
        "defaultMode": "local-only",
        "requireSignedAuthorization": True,
        "oneActionPerAuthorization": True,
        "maxAuthorizationSeconds": authorization_core.DEFAULT_AUTHORIZATION_SECONDS,
        "permitMaxAgeSeconds": EXTERNAL_ACTION_PERMIT_MAX_AGE_SECONDS,
        "allowedIdentityProviders": ["signed-local"],
        "protectedActions": list(authorization_core.ACTIONS),
    },
    "security": {
        "secretScanRequired": True,
        "sensitiveKeywords": [
            "auth",
            "login",
            "password",
            "token",
            "secret",
            "api key",
            "payment",
            "stripe",
            "webhook",
            "rbac",
            "permission",
            "pii",
            "personal data",
            "production",
        ],
    },
    "audit": {
        "defaultProfile": "standard",
        "releaseProfile": "release",
        "failOnSeverity": "high",
        "requiredDomains": [
            "correctness",
            "security",
            "maintainability",
            "architecture",
            "reliability",
        ],
        "networkAllowed": False,
        "automaticFixesAllowed": False,
        "arbitraryExecutablesAllowed": False,
        "rawSecretsAllowed": False,
        "incompleteCanPass": False,
        "suppressionRequiresOwner": True,
        "suppressionRequiresExpiry": True,
        "releaseRequiresAuditReceipt": False,
    },
    "quant": {
        "requiredEvidence": [
            "symbol",
            "timeframe",
            "date_range",
            "data_source",
            "history_quality_or_modelling_quality",
            "spread_model",
            "commission_model",
            "slippage_model",
            "source_version",
            "settings_file",
            "in_sample_out_of_sample_split",
            "walk_forward_or_forward_test_plan",
            "drawdown_stress_test",
            "no_lookahead_bias_review",
        ],
        "minimumHistoryQualityPercent": 99.0,
        "requiresParameterFreeze": True,
        "requiresOutOfSample": True,
        "requiresCostModel": True,
    },
    "program": {
        "maxPhases": 100,
        "maxParallelPhases": 4,
        "maxActiveMinutes": 525_600,
        "requireSignedApprovals": True,
        "requireCurrentEvidence": True,
        "requireFinalAudit": True,
        "allowedIdentityProviders": ["signed-local"],
    },
    "launch": {
        "requireReceiptForProduction": True,
        "requireProfileDeclaration": True,
        "maxEvidenceAgeMinutes": 1440,
        "requiredControlIds": [],
        "advisoryControlIds": [],
        "requireReleaseAuditForSurfaces": [
            "public-web",
            "commercial",
            "payments",
            "regulated-data",
        ],
        "allowWaivers": True,
    },
}


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def parse_simple_yaml(text: str) -> Optional[dict[str, Any]]:
    """Parse a conservative one-level YAML subset without external deps."""
    data: dict[str, Any] = {}
    current_key: Optional[str] = None
    for raw_line in text.splitlines():
        line_no_comment = raw_line.split("#", 1)[0].rstrip()
        if not line_no_comment.strip():
            continue
        indent = len(line_no_comment) - len(line_no_comment.lstrip(" "))
        line = line_no_comment.strip()
        if indent == 0 and ":" in line and not line.startswith("- "):
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip()
            data[current_key] = parse_scalar(value) if value else {}
            continue
        if current_key is None:
            continue
        if line.startswith("- "):
            if not isinstance(data.get(current_key), list):
                data[current_key] = []
            data[current_key].append(parse_scalar(line[2:]))
            continue
        if ":" in line:
            if not isinstance(data.get(current_key), dict):
                data[current_key] = {}
            key, value = line.split(":", 1)
            data[current_key][key.strip()] = parse_scalar(value)
    return data or None


def read_policy_file(project_path: Path, path: Path) -> Optional[dict[str, Any]]:
    try:
        relative = path.relative_to(project_path).as_posix()
        content = audit_core.read_repository_file(
            project_path,
            relative,
            max_bytes=1_000_000,
            max_seconds=10,
        )
        text = content.decode("utf-8-sig", errors="strict")
        if path.suffix.lower() == ".json":
            value = json.loads(text)
            return value if isinstance(value, dict) else None
        if path.suffix.lower() in {".yml", ".yaml"}:
            return parse_simple_yaml(text)
    except (ValueError, UnicodeError, json.JSONDecodeError, audit_core.AuditError):
        return None
    return None


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ToolError(f"JStack policy field '{field}' must be an array of non-empty strings.")
    return [item.strip() for item in value]


def _merge_unique(*groups: list[str]) -> list[str]:
    result: list[str] = []
    for group in groups:
        for item in group:
            if item not in result:
                result.append(item)
    return result


def validate_policy_override(value: dict[str, Any], path: Path) -> None:
    if not isinstance(value, dict):
        raise ToolError(f"JStack policy must be a JSON/YAML object: {path}")
    if "schemaVersion" in value and value["schemaVersion"] != "jstack.enterprise.v1":
        raise ToolError(f"Unsupported JStack policy schemaVersion in {path}: {value['schemaVersion']!r}")
    for field in ("requiredChecks", "protectedPaths"):
        if field in value:
            _string_list(value[field], field)
    for section in (
        "release",
        "externalActions",
        "security",
        "audit",
        "quant",
        "program",
        "launch",
    ):
        if section in value and not isinstance(value[section], dict):
            raise ToolError(f"JStack policy field '{section}' must be an object.")
    security = value.get("security") or {}
    if "sensitiveKeywords" in security:
        _string_list(security["sensitiveKeywords"], "security.sensitiveKeywords")
    audit = value.get("audit") or {}
    if "requiredDomains" in audit:
        configured_domains = _string_list(audit["requiredDomains"], "audit.requiredDomains")
        unsupported_domains = sorted(set(configured_domains) - set(audit_core.DOMAINS) - {"reliability"})
        if unsupported_domains:
            raise ToolError(
                "JStack policy audit.requiredDomains contains unsupported domains: "
                + ", ".join(unsupported_domains)
            )
    if "defaultProfile" in audit and audit["defaultProfile"] not in {"quick", "standard", "deep", "release"}:
        raise ToolError("JStack policy audit.defaultProfile must be quick, standard, deep, or release.")
    if "releaseProfile" in audit and audit["releaseProfile"] not in {"quick", "standard", "deep", "release"}:
        raise ToolError("JStack policy audit.releaseProfile must be quick, standard, deep, or release.")
    if "failOnSeverity" in audit and audit["failOnSeverity"] not in {"critical", "high", "medium", "low", "info"}:
        raise ToolError("JStack policy audit.failOnSeverity must be critical, high, medium, low, or info.")
    quant = value.get("quant") or {}
    if "requiredEvidence" in quant:
        _string_list(quant["requiredEvidence"], "quant.requiredEvidence")
    if "minimumHistoryQualityPercent" in quant:
        try:
            number = float(quant["minimumHistoryQualityPercent"])
        except (TypeError, ValueError) as exc:
            raise ToolError("JStack policy quant.minimumHistoryQualityPercent must be numeric.") from exc
        if not 0 <= number <= 100:
            raise ToolError("JStack policy quant.minimumHistoryQualityPercent must be between 0 and 100.")
    program_policy = value.get("program") or {}
    allowed_program_fields = {
        "maxPhases",
        "maxParallelPhases",
        "maxActiveMinutes",
        "requireSignedApprovals",
        "requireCurrentEvidence",
        "requireFinalAudit",
        "allowedIdentityProviders",
    }
    unknown_program_fields = sorted(set(program_policy) - allowed_program_fields)
    if unknown_program_fields:
        raise ToolError(
            "JStack policy program contains unsupported fields: "
            + ", ".join(unknown_program_fields)
        )
    for field, maximum in (
        ("maxPhases", program_core.MAX_PHASES),
        ("maxParallelPhases", program_core.MAX_PARALLEL_PHASES),
        ("maxActiveMinutes", program_core.MAX_ACTIVE_MINUTES),
    ):
        if field in program_policy:
            configured = program_policy[field]
            if (
                not isinstance(configured, int)
                or isinstance(configured, bool)
                or not 1 <= configured <= maximum
            ):
                raise ToolError(
                    "JStack policy program.%s must be an integer from 1 to %d."
                    % (field, maximum)
                )
    for field in (
        "requireSignedApprovals",
        "requireCurrentEvidence",
        "requireFinalAudit",
    ):
        if field in program_policy and not isinstance(program_policy[field], bool):
            raise ToolError("JStack policy program.%s must be boolean." % field)
    if "allowedIdentityProviders" in program_policy:
        providers = _string_list(
            program_policy["allowedIdentityProviders"],
            "program.allowedIdentityProviders",
        )
        if set(providers) - {"signed-local"}:
            raise ToolError(
                "JStack currently supports only the signed-local program identity provider."
            )
    launch_policy = value.get("launch") or {}
    allowed_launch_fields = {
        "requireReceiptForProduction",
        "requireProfileDeclaration",
        "maxEvidenceAgeMinutes",
        "requiredControlIds",
        "advisoryControlIds",
        "requireReleaseAuditForSurfaces",
        "allowWaivers",
    }
    unknown_launch_fields = sorted(set(launch_policy) - allowed_launch_fields)
    if unknown_launch_fields:
        raise ToolError(
            "JStack policy launch contains unsupported fields: "
            + ", ".join(unknown_launch_fields)
        )
    for field in (
        "requireReceiptForProduction",
        "requireProfileDeclaration",
        "allowWaivers",
    ):
        if field in launch_policy and not isinstance(launch_policy[field], bool):
            raise ToolError(f"JStack policy launch.{field} must be boolean.")
    if "maxEvidenceAgeMinutes" in launch_policy:
        configured_age = launch_policy["maxEvidenceAgeMinutes"]
        if (
            not isinstance(configured_age, int)
            or isinstance(configured_age, bool)
            or not 1 <= configured_age <= 1440
        ):
            raise ToolError(
                "JStack policy launch.maxEvidenceAgeMinutes must be an integer from 1 to 1440."
            )
    try:
        launch_controls = launch_core.control_index()
    except launch_core.LaunchError as exc:
        raise ToolError("The packaged JStack launch-control catalogue is invalid.") from exc
    required_launch_controls = _string_list(
        launch_policy.get("requiredControlIds", []),
        "launch.requiredControlIds",
    )
    advisory_launch_controls = _string_list(
        launch_policy.get("advisoryControlIds", []),
        "launch.advisoryControlIds",
    )
    unknown_launch_controls = sorted(
        (set(required_launch_controls) | set(advisory_launch_controls))
        - set(launch_controls)
    )
    if unknown_launch_controls:
        raise ToolError(
            "JStack policy launch references unknown control ids: "
            + ", ".join(unknown_launch_controls)
        )
    overlapping_launch_controls = sorted(
        set(required_launch_controls) & set(advisory_launch_controls)
    )
    if overlapping_launch_controls:
        raise ToolError(
            "JStack policy launch controls cannot be both required and advisory: "
            + ", ".join(overlapping_launch_controls)
        )
    release_audit_surfaces = _string_list(
        launch_policy.get("requireReleaseAuditForSurfaces", []),
        "launch.requireReleaseAuditForSurfaces",
    )
    unknown_launch_surfaces = sorted(
        set(release_audit_surfaces) - set(launch_core.SURFACE_IDS)
    )
    if unknown_launch_surfaces:
        raise ToolError(
            "JStack policy launch.requireReleaseAuditForSurfaces contains unsupported surfaces: "
            + ", ".join(unknown_launch_surfaces)
        )
    external_policy = value.get("externalActions") or {}
    allowed_external_fields = {
        "defaultMode",
        "requireSignedAuthorization",
        "oneActionPerAuthorization",
        "maxAuthorizationSeconds",
        "permitMaxAgeSeconds",
        "allowedIdentityProviders",
        "protectedActions",
    }
    unknown_external_fields = sorted(set(external_policy) - allowed_external_fields)
    if unknown_external_fields:
        raise ToolError(
            "JStack policy externalActions contains unsupported fields: "
            + ", ".join(unknown_external_fields)
        )
    if "defaultMode" in external_policy and external_policy["defaultMode"] != "local-only":
        raise ToolError("JStack policy externalActions.defaultMode must be local-only.")
    for field in ("requireSignedAuthorization", "oneActionPerAuthorization"):
        if field in external_policy and not isinstance(external_policy[field], bool):
            raise ToolError(f"JStack policy externalActions.{field} must be boolean.")
    for field, maximum in (
        ("maxAuthorizationSeconds", authorization_core.MAX_AUTHORIZATION_SECONDS),
        ("permitMaxAgeSeconds", EXTERNAL_ACTION_PERMIT_MAX_AGE_SECONDS),
    ):
        if field in external_policy:
            configured = external_policy[field]
            if (
                not isinstance(configured, int)
                or isinstance(configured, bool)
                or not 1 <= configured <= maximum
            ):
                raise ToolError(
                    f"JStack policy externalActions.{field} must be an integer from 1 to {maximum}."
                )
    if "allowedIdentityProviders" in external_policy:
        providers = _string_list(
            external_policy["allowedIdentityProviders"],
            "externalActions.allowedIdentityProviders",
        )
        if set(providers) - {"signed-local"}:
            raise ToolError(
                "JStack currently supports only the signed-local external-action identity provider."
            )
    if "protectedActions" in external_policy:
        actions = _string_list(
            external_policy["protectedActions"], "externalActions.protectedActions"
        )
        unsupported = sorted(set(actions) - set(authorization_core.ACTIONS))
        if unsupported:
            raise ToolError(
                "JStack policy externalActions.protectedActions contains unsupported actions: "
                + ", ".join(unsupported)
            )


def apply_policy_floors(policy: dict[str, Any], project_path: Path) -> dict[str, Any]:
    """Enforce minimum controls that a repository policy cannot weaken."""
    policy["schemaVersion"] = "jstack.enterprise.v1"
    policy["requiredChecks"] = _merge_unique(
        _string_list(DEFAULT_ENTERPRISE_POLICY["requiredChecks"], "requiredChecks"),
        _string_list(policy.get("requiredChecks", []), "requiredChecks"),
    )
    policy_files = []
    for candidate in policy_candidates(project_path):
        try:
            policy_files.append(candidate.relative_to(project_path).as_posix())
        except ValueError:
            continue
    policy["protectedPaths"] = _merge_unique(
        _string_list(DEFAULT_ENTERPRISE_POLICY["protectedPaths"], "protectedPaths"),
        _string_list(policy.get("protectedPaths", []), "protectedPaths"),
        policy_files,
    )
    for key in ("requiresExplicitApproval", "requiresRollbackPlan", "requiresCanaryOrMonitoring", "requiresCleanDiffCheck"):
        policy.setdefault("release", {})[key] = True
    external_policy = policy.setdefault("externalActions", {})
    default_external = DEFAULT_ENTERPRISE_POLICY["externalActions"]
    external_policy["defaultMode"] = "local-only"
    external_policy["requireSignedAuthorization"] = True
    external_policy["oneActionPerAuthorization"] = True
    external_policy["maxAuthorizationSeconds"] = min(
        int(external_policy.get("maxAuthorizationSeconds", default_external["maxAuthorizationSeconds"])),
        int(default_external["maxAuthorizationSeconds"]),
        authorization_core.MAX_AUTHORIZATION_SECONDS,
    )
    external_policy["permitMaxAgeSeconds"] = min(
        int(external_policy.get("permitMaxAgeSeconds", default_external["permitMaxAgeSeconds"])),
        int(default_external["permitMaxAgeSeconds"]),
        EXTERNAL_ACTION_PERMIT_MAX_AGE_SECONDS,
    )
    external_policy["allowedIdentityProviders"] = ["signed-local"]
    external_policy["protectedActions"] = _merge_unique(
        list(authorization_core.ACTIONS),
        _string_list(
            external_policy.get("protectedActions", []),
            "externalActions.protectedActions",
        ),
    )
    policy.setdefault("security", {})["secretScanRequired"] = True
    policy["security"]["sensitiveKeywords"] = _merge_unique(
        _string_list(DEFAULT_ENTERPRISE_POLICY["security"]["sensitiveKeywords"], "security.sensitiveKeywords"),
        _string_list(policy["security"].get("sensitiveKeywords", []), "security.sensitiveKeywords"),
    )
    audit = policy.setdefault("audit", {})
    default_audit = DEFAULT_ENTERPRISE_POLICY["audit"]
    audit["releaseProfile"] = "release"
    audit["networkAllowed"] = False
    audit["automaticFixesAllowed"] = False
    audit["arbitraryExecutablesAllowed"] = False
    audit["rawSecretsAllowed"] = False
    audit["incompleteCanPass"] = False
    audit["suppressionRequiresOwner"] = True
    audit["suppressionRequiresExpiry"] = True
    audit["requiredDomains"] = _merge_unique(
        _string_list(default_audit["requiredDomains"], "audit.requiredDomains"),
        _string_list(audit.get("requiredDomains", []), "audit.requiredDomains"),
    )
    audit.setdefault("defaultProfile", default_audit["defaultProfile"])
    severity_order = ["info", "low", "medium", "high", "critical"]
    configured_threshold = str(audit.get("failOnSeverity") or default_audit["failOnSeverity"])
    audit["failOnSeverity"] = severity_order[
        min(severity_order.index("high"), severity_order.index(configured_threshold))
    ]
    audit["releaseRequiresAuditReceipt"] = bool(audit.get("releaseRequiresAuditReceipt", False))
    policy.setdefault("quant", {})["requiresParameterFreeze"] = True
    policy["quant"]["requiresOutOfSample"] = True
    policy["quant"]["requiresCostModel"] = True
    policy["quant"]["requiredEvidence"] = _merge_unique(
        _string_list(DEFAULT_ENTERPRISE_POLICY["quant"]["requiredEvidence"], "quant.requiredEvidence"),
        _string_list(policy["quant"].get("requiredEvidence", []), "quant.requiredEvidence"),
    )
    policy["quant"]["minimumHistoryQualityPercent"] = max(
        float(DEFAULT_ENTERPRISE_POLICY["quant"]["minimumHistoryQualityPercent"]),
        float(policy["quant"].get("minimumHistoryQualityPercent", 0)),
    )
    program_policy = policy.setdefault("program", {})
    default_program = DEFAULT_ENTERPRISE_POLICY["program"]
    for field, absolute in (
        ("maxPhases", program_core.MAX_PHASES),
        ("maxParallelPhases", program_core.MAX_PARALLEL_PHASES),
        ("maxActiveMinutes", program_core.MAX_ACTIVE_MINUTES),
    ):
        program_policy[field] = min(
            int(program_policy.get(field, default_program[field])),
            int(default_program[field]),
            absolute,
        )
    program_policy["requireSignedApprovals"] = True
    program_policy["requireCurrentEvidence"] = True
    program_policy["requireFinalAudit"] = True
    program_policy["allowedIdentityProviders"] = ["signed-local"]
    launch_policy = policy.setdefault("launch", {})
    default_launch = DEFAULT_ENTERPRISE_POLICY["launch"]
    launch_policy["requireReceiptForProduction"] = True
    launch_policy["requireProfileDeclaration"] = True
    launch_policy["maxEvidenceAgeMinutes"] = min(
        int(
            launch_policy.get(
                "maxEvidenceAgeMinutes",
                default_launch["maxEvidenceAgeMinutes"],
            )
        ),
        int(default_launch["maxEvidenceAgeMinutes"]),
        1440,
    )
    launch_policy["requiredControlIds"] = _merge_unique(
        _string_list(default_launch["requiredControlIds"], "launch.requiredControlIds"),
        _string_list(
            launch_policy.get("requiredControlIds", []),
            "launch.requiredControlIds",
        ),
    )
    launch_policy["advisoryControlIds"] = _merge_unique(
        _string_list(default_launch["advisoryControlIds"], "launch.advisoryControlIds"),
        _string_list(
            launch_policy.get("advisoryControlIds", []),
            "launch.advisoryControlIds",
        ),
    )
    launch_policy["requireReleaseAuditForSurfaces"] = _merge_unique(
        _string_list(
            default_launch["requireReleaseAuditForSurfaces"],
            "launch.requireReleaseAuditForSurfaces",
        ),
        _string_list(
            launch_policy.get("requireReleaseAuditForSurfaces", []),
            "launch.requireReleaseAuditForSurfaces",
        ),
    )
    launch_policy["allowWaivers"] = bool(
        launch_policy.get("allowWaivers", default_launch["allowWaivers"])
    )
    return policy


def policy_candidates(project_path: Path) -> list[Path]:
    return [
        project_path / "jstack.enterprise.json",
        project_path / "jstack.policy.json",
        project_path / "jstack.json",
        project_path / "jstack.yml",
        project_path / "jstack.yaml",
        project_path / ".jstack" / "jstack.enterprise.json",
        project_path / ".jstack" / "jstack.policy.json",
        project_path / ".jstack" / "jstack.yml",
        project_path / ".jstack" / "jstack.yaml",
        project_path / "gstack.enterprise.json",
        project_path / "gstack.policy.json",
        project_path / "gstack.json",
        project_path / "gstack.yml",
        project_path / "gstack.yaml",
        project_path / ".gstack" / "gstack.enterprise.json",
        project_path / ".gstack" / "gstack.policy.json",
        project_path / ".gstack" / "gstack.yml",
        project_path / ".gstack" / "gstack.yaml",
    ]


def load_enterprise_policy(project_path: Path) -> dict[str, Any]:
    project_path = project_path.resolve()
    existing = [path for path in policy_candidates(project_path) if path.exists() or path.is_symlink()]
    if len(existing) > 1:
        raise ToolError(
            "Multiple JStack policy files are ambiguous; keep exactly one: " + ", ".join(str(path) for path in existing)
        )
    for path in existing:
        if path.is_symlink():
            raise ToolError(f"JStack policy file may not be a symlink: {path}")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_000_000:
            raise ToolError(f"JStack policy must be a regular file no larger than 1 MB: {path}")
        parsed = read_policy_file(project_path, path)
        if parsed is None:
            raise ToolError(f"Could not parse JStack policy file: {path}")
        validate_policy_override(parsed, path)
        policy = apply_policy_floors(deep_merge(DEFAULT_ENTERPRISE_POLICY, parsed), project_path)
        policy["_sourcePath"] = str(path)
        policy["_usingDefault"] = False
        return policy
    policy = apply_policy_floors(json.loads(json.dumps(DEFAULT_ENTERPRISE_POLICY)), project_path)
    policy["_sourcePath"] = None
    policy["_usingDefault"] = True
    return policy


def _git_text(result: dict[str, Any]) -> str:
    stdout = result.get("stdout", b"")
    return stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else str(stdout)


def resolve_base_ref(project_path: Path, requested: Optional[str] = None) -> dict[str, Any]:
    candidates = [requested] if requested else ["@{upstream}", "origin/main", "origin/master", "main", "master"]
    for candidate in candidates:
        if not candidate:
            continue
        verify = run_complete(["git", "rev-parse", "--verify", f"{candidate}^{{commit}}"], project_path, timeout=8)
        if not verify["ok"]:
            continue
        merge_base = run_complete(["git", "merge-base", str(candidate), "HEAD"], project_path, timeout=8)
        if merge_base["ok"]:
            return {
                "requested": requested,
                "resolvedRef": str(candidate),
                "baseCommit": _git_text(merge_base).strip(),
            }
    if requested:
        raise ToolError(f"Could not resolve requested base_ref: {requested}")
    return {"requested": None, "resolvedRef": None, "baseCommit": None}


def git_change_evidence(project_path: Path, base_ref: Optional[str] = None) -> dict[str, Any]:
    root_raw = git_root(project_path)
    if not root_raw:
        raise ToolError(f"JStack change evidence requires a git repository: {project_path}")
    root = Path(root_raw).resolve()
    base = resolve_base_ref(root, base_ref)
    commands: list[tuple[str, list[str]]] = []
    if base["baseCommit"]:
        commands.append(("committed", ["git", "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", f"{base['baseCommit']}..HEAD", "--"]))
    commands.extend(
        [
            ("unstaged", ["git", "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "--"]),
            ("staged", ["git", "diff", "--no-ext-diff", "--no-textconv", "--cached", "--name-only", "-z", "--"]),
            ("untracked", ["git", "ls-files", "--others", "--exclude-standard", "-z"]),
        ]
    )
    seen: set[str] = set()
    files: list[str] = []
    sources: dict[str, list[str]] = {}
    for source, command in commands:
        result = run_complete(command, root, timeout=15, max_bytes=10_000_000)
        if not result["ok"]:
            raise ToolError(f"Could not collect {source} git change evidence: {result['stderr']}")
        source_files: list[str] = []
        for raw in result["stdout"].split(b"\0"):
            item = decode_git_relative_path(raw, "changed") if raw else ""
            if item and item not in seen:
                seen.add(item)
                files.append(item)
            if item:
                source_files.append(item)
        sources[source] = source_files
        if len(files) > MAX_CHANGED_FILES:
            raise ToolError(f"Changed-file evidence exceeds the {MAX_CHANGED_FILES}-file safety limit.")
    return {
        "gitRoot": str(root),
        "baseRef": base["resolvedRef"],
        "baseCommit": base["baseCommit"],
        "files": files,
        "sources": sources,
        "complete": True,
    }


def git_changed_files(project_path: Path, base_ref: Optional[str] = None) -> list[str]:
    return git_change_evidence(project_path, base_ref)["files"]


def project_state(project_path: Path) -> dict[str, Any]:
    root_raw = git_root(project_path)
    if not root_raw:
        raise ToolError("JStack evidence receipts require a git repository with a committed revision.")
    root = Path(root_raw).resolve()
    head_result = run_complete(["git", "rev-parse", "HEAD"], root, timeout=8)
    if not head_result["ok"]:
        raise ToolError("JStack evidence receipts require a valid git HEAD commit.")
    head = _git_text(head_result).strip()
    status_result = run_complete(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        root,
        timeout=15,
        max_bytes=20_000_000,
    )
    tracked_result = run_complete(
        ["git", "ls-files", "-s", "-z"],
        root,
        timeout=20,
        max_bytes=20_000_000,
    )
    flags_result = run_complete(
        ["git", "ls-files", "-v", "-z"],
        root,
        timeout=20,
        max_bytes=20_000_000,
    )
    untracked_result = run_complete(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        root,
        timeout=15,
        max_bytes=20_000_000,
    )
    for label, result in (
        ("status", status_result),
        ("tracked index", tracked_result),
        ("index flags", flags_result),
        ("untracked", untracked_result),
    ):
        if not result["ok"]:
            raise ToolError(f"Could not fingerprint project {label}: {result['stderr']}")
    digest = hashlib.sha256()
    digest.update(str(root).encode("utf-8"))
    digest.update(b"\0")
    digest.update(head.encode("ascii"))
    digest.update(b"\0")
    digest.update(status_result["stdout"])
    digest.update(b"\0")
    digest.update(flags_result["stdout"])
    total_bytes = 0
    fingerprinted_files = 0

    def hash_regular_file(relative: str, label: str) -> None:
        nonlocal total_bytes, fingerprinted_files
        remaining = MAX_FINGERPRINT_BYTES - total_bytes
        if remaining <= 0:
            raise ToolError(
                f"Project fingerprint exceeds the {MAX_FINGERPRINT_BYTES}-byte safety limit."
            )
        try:
            size, file_digest = audit_core.digest_repository_file(
                root,
                relative,
                max_bytes=remaining,
                max_seconds=30,
            )
        except audit_core.AuditError as exc:
            raise ToolError(f"Cannot fingerprint regular file safely: {label}") from exc
        fingerprinted_files += 1
        if fingerprinted_files > MAX_FINGERPRINT_FILES:
            raise ToolError(f"Project fingerprint exceeds the {MAX_FINGERPRINT_FILES}-file safety limit.")
        total_bytes += size
        digest.update(b"<sha256>")
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_digest))

    tracked: list[str] = []
    submodules_present = False
    for raw in tracked_result["stdout"].split(b"\0"):
        if not raw:
            continue
        try:
            index_meta, path_raw = raw.split(b"\t", 1)
            relative = decode_git_relative_path(path_raw, "tracked index entry")
        except ValueError as exc:
            raise ToolError("Git returned a tracked index entry that cannot be represented safely.") from exc
        candidate = root / relative
        digest.update(index_meta)
        digest.update(b"\t")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            digest.update(b"<missing>")
        else:
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(candidate).encode("utf-8", errors="surrogateescape")
                total_bytes += len(target)
                if total_bytes > MAX_FINGERPRINT_BYTES:
                    raise ToolError(
                        f"Project fingerprint exceeds the {MAX_FINGERPRINT_BYTES}-byte safety limit."
                    )
                digest.update(b"<symlink>")
                digest.update(target)
            elif stat.S_ISREG(metadata.st_mode):
                try:
                    candidate.resolve().relative_to(root)
                except ValueError as exc:
                    raise ToolError(f"Tracked file resolves outside the repository: {relative}") from exc
                hash_regular_file(relative, relative)
            elif stat.S_ISDIR(metadata.st_mode) and index_meta.startswith(b"160000 "):
                submodules_present = True
                digest.update(b"<gitlink>")
            else:
                raise ToolError(f"Cannot fingerprint tracked non-regular path: {relative}")
        tracked.append(relative)

    if submodules_present:
        submodules = run_complete(
            ["git", "submodule", "status", "--recursive"],
            root,
            timeout=30,
            max_bytes=5_000_000,
        )
        if not submodules["ok"]:
            raise ToolError(f"Could not fingerprint submodules: {submodules['stderr']}")
        digest.update(submodules["stdout"])

    hidden_index_flags: list[str] = []
    for raw in flags_result["stdout"].split(b"\0"):
        if len(raw) < 3:
            continue
        tag = chr(raw[0])
        if tag.islower() or tag == "S":
            hidden_index_flags.append(
                decode_git_relative_path(raw[2:], "index-flag")
            )

    untracked: list[str] = []
    for raw in untracked_result["stdout"].split(b"\0"):
        if not raw:
            continue
        relative = decode_git_relative_path(raw, "untracked")
        candidate = root / relative
        if candidate.is_symlink():
            raise ToolError(f"Cannot fingerprint symlinked untracked path: {relative}")
        path = candidate.resolve(strict=False)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ToolError(f"Untracked path escapes repository root: {relative}") from exc
        if not path.is_file():
            raise ToolError(f"Cannot fingerprint non-regular untracked path: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        hash_regular_file(relative, relative)
        untracked.append(relative)
    return {
        "gitRoot": str(root),
        "gitHead": head,
        "projectFingerprint": digest.hexdigest(),
        "clean": not bool(status_result["stdout"]) and not hidden_index_flags,
        "trackedFileCount": len(tracked),
        "fingerprintedBytes": total_bytes,
        "hiddenIndexFlags": hidden_index_flags,
        "untrackedFiles": untracked,
    }


def evidence_subject(project_path: Path, base_ref: Optional[str] = None) -> dict[str, Any]:
    state = project_state(project_path)
    base = resolve_base_ref(Path(state["gitRoot"]), base_ref) if base_ref else {
        "requested": None,
        "resolvedRef": None,
        "baseCommit": None,
    }
    policy = load_enterprise_policy(Path(state["gitRoot"]))
    public_policy = {key: value for key, value in policy.items() if not key.startswith("_")}
    policy_digest = hashlib.sha256(
        json.dumps(public_policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        **state,
        "baseRef": base["resolvedRef"],
        "baseCommit": base["baseCommit"],
        "policyDigest": policy_digest,
        "toolVersion": SERVER_VERSION,
    }


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_receipt(payload: dict[str, Any]) -> str:
    body = dict(payload)
    body["serverSession"] = SERVER_SESSION_ID
    body["issuedAt"] = now_iso()
    encoded = _b64encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64encode(hmac.new(_RECEIPT_SECRET, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def verify_signed_session_token(token: str, expected_kind: str) -> dict[str, Any]:
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = _b64encode(
            hmac.new(_RECEIPT_SECRET, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("signature mismatch")
        payload = json.loads(_b64decode(encoded).decode("utf-8"))
        issued = _dt.datetime.fromisoformat(str(payload["issuedAt"]))
        expires = _dt.datetime.fromisoformat(str(payload["expiresAt"]))
        if issued.tzinfo is None or expires.tzinfo is None:
            raise ValueError("timezone-aware timestamps required")
    except Exception as exc:
        raise ToolError(
            "Audit session token is malformed, expired, or was not issued by this JStack server session."
        ) from exc
    now = _dt.datetime.now(_dt.timezone.utc)
    checks = {
        "kind": payload.get("kind") == expected_kind,
        "session": payload.get("serverSession") == SERVER_SESSION_ID,
        "fresh": issued <= now < expires,
        "boundedExpiry": 0 < (expires - issued).total_seconds() <= RECEIPT_MAX_AGE_SECONDS,
    }
    if not all(checks.values()):
        raise ToolError("Audit session token is stale or does not match this JStack server session.")
    return payload


def verify_receipt(
    receipt: str,
    expected_kind: str,
    state: dict[str, Any],
    expected_subject: Optional[dict[str, Any]] = None,
    require_passed: bool = True,
) -> dict[str, Any]:
    try:
        encoded, supplied_signature = receipt.split(".", 1)
        expected_signature = _b64encode(hmac.new(_RECEIPT_SECRET, encoded.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("signature mismatch")
        payload = json.loads(_b64decode(encoded).decode("utf-8"))
        issued = _dt.datetime.fromisoformat(str(payload["issuedAt"]))
        if issued.tzinfo is None:
            raise ValueError("timezone-aware issuedAt required")
        expires = None
        if payload.get("expiresAt") is not None:
            expires = _dt.datetime.fromisoformat(str(payload["expiresAt"]))
            if expires.tzinfo is None:
                raise ValueError("timezone-aware expiresAt required")
    except Exception as exc:
        raise ToolError("Evidence receipt is malformed, expired, or was not issued by this JStack server session.") from exc
    age = (_dt.datetime.now(_dt.timezone.utc) - issued).total_seconds()
    checks = {
        "kind": payload.get("kind") == expected_kind,
        "session": payload.get("serverSession") == SERVER_SESSION_ID,
        "projectPath": payload.get("projectPath") == state["gitRoot"],
        "gitHead": payload.get("gitHead") == state["gitHead"],
        "projectFingerprint": payload.get("projectFingerprint") == state["projectFingerprint"],
        "fresh": 0 <= age <= RECEIPT_MAX_AGE_SECONDS,
    }
    if require_passed:
        checks["passed"] = payload.get("passed") is True
    if expires is not None:
        now = _dt.datetime.now(_dt.timezone.utc)
        checks["notExpired"] = issued <= now < expires
        checks["boundedExpiry"] = 0 < (expires - issued).total_seconds() <= RECEIPT_MAX_AGE_SECONDS
    if expected_subject:
        for field in ("baseCommit", "policyDigest", "toolVersion"):
            checks[field] = payload.get(field) == expected_subject.get(field)
    return {"valid": all(checks.values()), "checks": checks, "payload": payload}


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json_text(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def path_matches_patterns(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern.replace("\\", "/")) for pattern in patterns)


def goal_is_sensitive(goal: str, policy: dict[str, Any]) -> bool:
    goal_l = goal.lower()
    keywords = policy.get("security", {}).get("sensitiveKeywords") or []
    return any(str(keyword).lower() in goal_l for keyword in keywords)


def percentage_from_text(text: str, labels: list[str]) -> Optional[float]:
    for label in labels:
        pattern = re.compile(re.escape(label) + r"[^0-9]{0,40}([0-9]+(?:\.[0-9]+)?)\s*%", re.IGNORECASE)
        match = pattern.search(text)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
    return None


def package_scripts(project_path: Path) -> dict[str, str]:
    package_json = project_path / "package.json"
    data = read_json(package_json)
    if not data:
        return {}
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {str(key): str(value) for key, value in scripts.items()}


def discover_test_commands(project_path: Path) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    scripts = package_scripts(project_path)
    for script_name in ["test", "lint", "typecheck", "type-check", "build"]:
        if script_name in scripts:
            kind = "typecheck" if script_name == "type-check" else script_name
            commands.append(
                {
                    "key": f"npm:{script_name}",
                    "kind": kind,
                    "label": f"npm run {script_name}" if script_name != "test" else "npm test",
                    "source": "package.json",
                    "script": scripts[script_name],
                    "args": ["npm", "test"] if script_name == "test" else ["npm", "run", script_name],
                }
            )
    tests_dir = project_path / "tests"
    pyproject = project_path / "pyproject.toml"
    pyproject_text = pyproject.read_text(encoding="utf-8-sig", errors="replace") if pyproject.exists() else ""
    pytest_detected = (project_path / "pytest.ini").exists() or "pytest" in pyproject_text.lower()
    if tests_dir.exists() and pytest_detected:
        commands.append(
            {
                "key": "python:pytest",
                "kind": "test",
                "label": "python3 -m pytest",
                "source": "python project detection",
                "args": ["python3", "-m", "pytest"],
            }
        )
    elif tests_dir.exists():
        commands.append(
            {
                "key": "python:unittest",
                "kind": "test",
                "label": "python3 -m unittest discover -s tests -v",
                "source": "tests directory",
                "args": ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
            }
        )
    if (project_path / "Cargo.toml").exists():
        commands.append({"key": "cargo:test", "kind": "test", "label": "cargo test", "source": "Cargo.toml", "args": ["cargo", "test"]})
    if (project_path / "go.mod").exists():
        commands.append({"key": "go:test", "kind": "test", "label": "go test ./...", "source": "go.mod", "args": ["go", "test", "./..."]})
    for command in commands:
        fingerprint_input = json.dumps(
            {key: command.get(key) for key in ("key", "kind", "source", "script", "args")},
            sort_keys=True,
            separators=(",", ":"),
        )
        command["commandFingerprint"] = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
        command["executesProjectCode"] = True
    return commands


def approved_command_env(allowlist: list[str], isolated_home: Path, project_path: Path) -> dict[str, str]:
    safe_names = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TEMP",
        "TMP",
    }
    env = {name: value for name, value in os.environ.items() if name.upper() in safe_names}
    for name in allowlist:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ToolError(f"Invalid env_allowlist name: {name!r}")
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(
        {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "XDG_CONFIG_HOME": str(isolated_home / ".config"),
            "XDG_CACHE_HOME": str(isolated_home / ".cache"),
            "CI": "1",
            "NO_COLOR": "1",
            "JSTACK_QA_EXECUTION": "1",
        }
    )
    trusted_path_entries: list[str] = []
    for entry in env.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        resolved = Path(entry).resolve()
        try:
            resolved.relative_to(project_path)
            continue
        except ValueError:
            pass
        if str(resolved) not in trusted_path_entries:
            trusted_path_entries.append(str(resolved))
    for entry in (Path(sys.executable).resolve().parent, Path("/usr/bin"), Path("/bin"), Path("/usr/local/bin"), Path("/opt/homebrew/bin")):
        if entry.exists() and str(entry) not in trusted_path_entries:
            trusted_path_entries.append(str(entry))
    env["PATH"] = os.pathsep.join(trusted_path_entries)
    return env


def run_approved_project_command(
    command: list[str],
    project_path: Path,
    timeout: int,
    env_allowlist: list[str],
    fixed_env: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    output_limit = 1_000_000

    def terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            system_root = Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or "C:/Windows")
            taskkill = system_root / "System32" / "taskkill.exe"
            if taskkill.is_file():
                try:
                    subprocess.run(
                        [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
            else:
                process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)

    with tempfile.TemporaryDirectory(prefix="jstack-qa-") as temp_home:
        env = approved_command_env(env_allowlist, Path(temp_home), project_path)
        for name, value in (fixed_env or {}).items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ToolError(f"Invalid fixed command environment name: {name!r}")
            if not isinstance(value, str) or "\x00" in value:
                raise ToolError(f"Invalid fixed command environment value for {name!r}.")
            env[name] = value
        executable = sys.executable if command[0] in {"python", "python3", "py"} else shutil.which(command[0], path=env["PATH"])
        if not executable:
            return {
                "ok": False,
                "returncode": 127,
                "stdout": "",
                "stderr": f"Command not found outside the project: {command[0]}",
                "args": command,
            }
        executable_path = Path(executable).resolve()
        try:
            executable_path.relative_to(project_path)
            return {
                "ok": False,
                "returncode": 126,
                "stdout": "",
                "stderr": f"Refusing to execute a project-local command binary: {executable_path}",
                "args": command,
            }
        except ValueError:
            pass
        resolved_command = [str(executable_path), *command[1:]]
        try:
            process = subprocess.Popen(
                resolved_command,
                cwd=str(project_path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=(os.name != "nt"),
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if os.name == "nt"
                    else 0
                ),
            )
        except FileNotFoundError:
            return {
                "ok": False,
                "returncode": 127,
                "stdout": "",
                "stderr": f"Command not found: {command[0]}",
                "args": command,
            }
        assert process.stdout and process.stderr
        overflow = threading.Event()
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()

        def read_stream(stream: Any, buffer: bytearray) -> None:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                remaining = output_limit - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
                    return

        readers = [
            threading.Thread(target=read_stream, args=(process.stdout, stdout_buffer), daemon=True),
            threading.Thread(target=read_stream, args=(process.stderr, stderr_buffer), daemon=True),
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        timed_out = False
        while process.poll() is None:
            if overflow.is_set():
                terminate(process)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                terminate(process)
                break
            time.sleep(0.02)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
        stdout_bytes = bytes(stdout_buffer)
        stderr_bytes = bytes(stderr_buffer)
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        capture_evidence = {
            "stdoutSha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderrSha256": hashlib.sha256(stderr_bytes).hexdigest(),
            "capturedOutputBytes": len(stdout_bytes) + len(stderr_bytes),
        }
        if timed_out:
            return {
                "ok": False,
                "returncode": 124,
                "stdout": truncate(stdout),
                "stderr": truncate(stderr + f"\nTimed out after {timeout}s; process group terminated."),
                "args": resolved_command,
                **capture_evidence,
            }
        if overflow.is_set():
            return {
                "ok": False,
                "returncode": 125,
                "stdout": truncate(stdout),
                "stderr": truncate(stderr + f"\nOutput exceeded {output_limit} bytes; process group terminated."),
                "args": resolved_command,
                **capture_evidence,
            }
    return {
        "ok": process.returncode == 0,
        "returncode": process.returncode,
        "stdout": truncate(stdout or ""),
        "stderr": truncate(stderr or ""),
        "args": resolved_command,
        **capture_evidence,
    }


def skill_files() -> list[Path]:
    files: list[Path] = []
    jstack_root = find_jstack_root()
    if jstack_root:
        bundled = jstack_root / "skills" / "jstack-dev" / "SKILL.md"
        audit_skill = jstack_root / "skills" / "jstack-audit" / "SKILL.md"
        direct = jstack_root / "SKILL.md"
        for candidate in (bundled, audit_skill, direct):
            if candidate.exists() and candidate not in files:
                files.append(candidate)
    root = find_gstack_root()
    if not root:
        return files
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if child.name in EXCLUDED_DIRS or child.name == "node_modules":
            continue
        skill_file = child / "SKILL.md"
        if skill_file.exists():
            if skill_file not in files:
                files.append(skill_file)
    root_skill = root / "SKILL.md"
    if root_skill.exists():
        if root_skill not in files:
            files.append(root_skill)
    return files


def parse_skill(skill_file: Path) -> dict[str, Any]:
    text = skill_file.read_text(encoding="utf-8", errors="replace")
    name = skill_file.parent.name
    description = ""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1]
            name_match = re.search(r"^name:\s*(.+)$", frontmatter, re.MULTILINE)
            if name_match:
                name = name_match.group(1).strip().strip('"')
            desc_match = re.search(r"^description:\s*(?:\|\s*)?\n(?P<body>(?:\s+.+\n?)+)", frontmatter, re.MULTILINE)
            if desc_match:
                description = " ".join(line.strip() for line in desc_match.group("body").splitlines()).strip()
            else:
                one_line = re.search(r"^description:\s*(.+)$", frontmatter, re.MULTILINE)
                if one_line:
                    description = one_line.group(1).strip().strip('"')
    if not description:
        body = text.split("\n", 8)
        description = " ".join(line.strip("# ").strip() for line in body[:8] if line.strip())[:500]
    return {
        "name": name,
        "path": str(skill_file),
        "directory": skill_file.parent.name,
        "description": truncate(description, 800),
    }


WORK_CLASSIFICATIONS = [
    {
        "id": "trivial",
        "label": "Trivial fix",
        "patterns": [r"\btypo\b", r"\bone[- ]line\b", r"\bcopy\b", r"\bsmall\b", r"\bsimple\b"],
        "skills": ["health", "review"],
        "requiredGates": ["context", "quality", "handoff"],
        "releaseBlockers": ["Unexpected broad diff for a trivial task."],
    },
    {
        "id": "normal",
        "label": "Normal feature or bug",
        "patterns": [r"\bfeature\b", r"\bbug\b", r"\bfix\b", r"\bchange\b", r"\bimplement\b"],
        "skills": ["spec", "plan-eng-review", "health", "review", "qa", "context-save"],
        "requiredGates": ["context", "planning", "build", "quality", "handoff"],
        "releaseBlockers": ["No focused verification for changed behavior."],
    },
    {
        "id": "architecture",
        "label": "Architecture-sensitive change",
        "patterns": [
            r"architecture",
            r"database",
            r"schema",
            r"migration",
            r"api contract",
            r"refactor",
            r"multi[- ]module",
            r"integration",
        ],
        "skills": ["spec", "autoplan", "plan-eng-review", "health", "review", "context-save"],
        "requiredGates": ["context", "planning", "safety", "build", "quality", "handoff"],
        "releaseBlockers": ["Architecture/data/API impact not reviewed before implementation."],
    },
    {
        "id": "product",
        "label": "Product or feature-shaping work",
        "patterns": [r"product", r"roadmap", r"requirements", r"workflow", r"persona", r"pricing", r"moneti[sz]ation"],
        "skills": ["office-hours", "spec", "autoplan", "plan-ceo-review", "context-save"],
        "requiredGates": ["context", "planning", "handoff"],
        "releaseBlockers": ["Acceptance criteria or user/workflow impact is unclear."],
    },
    {
        "id": "ui_product",
        "label": "UI/product-sensitive change",
        "patterns": [r"\bui\b", r"\bux\b", r"visual", r"layout", r"frontend", r"design", r"responsive", r"screen"],
        "skills": ["plan-design-review", "design-review", "design-consultation", "qa", "browse", "context-save"],
        "requiredGates": ["context", "planning", "build", "product-ui-qa", "quality", "handoff"],
        "releaseBlockers": ["No visual/browser QA for user-facing UI changes."],
    },
    {
        "id": "security_compliance",
        "label": "Security/compliance-sensitive change",
        "patterns": [
            r"auth",
            r"oauth",
            r"rbac",
            r"permission",
            r"secret",
            r"credential",
            r"password",
            r"token",
            r"payment",
            r"pii",
            r"compliance",
            r"webhook",
            r"public endpoint",
        ],
        "skills": ["cso", "guard", "careful", "health", "review", "qa", "context-save"],
        "requiredGates": ["context", "planning", "safety", "build", "security-compliance", "quality", "handoff"],
        "releaseBlockers": ["No security review for auth/secrets/data/public-boundary changes."],
    },
    {
        "id": "data_financial",
        "label": "Data/financial/integration-sensitive change",
        "patterns": [
            r"data",
            r"market",
            r"financial",
            r"calculation",
            r"metric",
            r"report",
            r"csv",
            r"import",
            r"export",
            r"provider",
            r"api",
        ],
        "skills": ["spec", "plan-eng-review", "cso", "health", "review", "qa", "document-release"],
        "requiredGates": ["context", "planning", "build", "security-compliance", "quality", "handoff"],
        "releaseBlockers": ["No verification for calculation/data/source-attribution behavior."],
    },
    {
        "id": "production_release",
        "label": "Production/release/deploy work",
        "patterns": [r"deploy", r"release", r"ship", r"merge", r"production", r"canary", r"domain", r"dns", r"ssl"],
        "skills": ["ship", "land-and-deploy", "canary", "qa", "cso", "context-save", "document-release"],
        "requiredGates": ["context", "planning", "safety", "build", "security-compliance", "quality", "release", "handoff"],
        "releaseBlockers": ["Release/deploy/production action lacks explicit user approval."],
    },
]

WORKFLOW_PROFILE = [
    {
        "category": "Classify",
        "skills": [],
        "purpose": "Classify the task by risk before choosing the light or enterprise path.",
    },
    {
        "category": "Context",
        "skills": ["context-restore"],
        "purpose": "Read project instructions, restore prior context, detect project boundaries, and load Caberg/Obsidian memory when relevant.",
    },
    {
        "category": "Planning",
        "skills": ["spec", "office-hours", "autoplan", "plan-eng-review", "plan-ceo-review", "plan-design-review", "plan-devex-review"],
        "purpose": "Turn unclear work into acceptance criteria and validate architecture, product, design, or developer experience before implementation.",
    },
    {
        "category": "Safety",
        "skills": ["guard", "freeze", "careful"],
        "purpose": "Constrain risky edit scope and prevent destructive or production-affecting operations without explicit approval.",
    },
    {
        "category": "Build",
        "skills": [],
        "purpose": "Implement the smallest coherent change using existing architecture and proportional tests.",
    },
    {
        "category": "Code quality",
        "skills": ["health", "review", "investigate"],
        "purpose": "Check repo health, review diffs for bugs/regressions, and investigate root causes before or after changing code.",
    },
    {
        "category": "Security/compliance",
        "skills": ["cso", "guard", "careful"],
        "purpose": "Audit auth, secrets, RBAC, payments, PII, public endpoints, external integrations, infrastructure, and compliance-sensitive changes.",
    },
    {
        "category": "Product/UI/QA",
        "skills": ["design-review", "design-consultation", "qa", "qa-only", "browse", "benchmark"],
        "purpose": "Verify visual/product quality, user-facing flows, browser behavior, and performance where applicable.",
    },
    {
        "category": "Release",
        "skills": ["ship", "land-and-deploy", "canary"],
        "purpose": "Run release checks and production monitoring only when the user explicitly asks to ship, merge, release, or deploy.",
    },
    {
        "category": "Handoff",
        "skills": ["context-save", "document-release", "learn"],
        "purpose": "Preserve decisions, verification, risks, next steps, and durable project memory.",
    },
]

MASTERY_STAGES = [
    {
        "stage": 0,
        "name": "Operator setup",
        "outcome": "Navigate repos, shells, logs, git state, and environments without accidental destructive actions.",
        "corePrinciples": ["Know the current path", "Inspect before changing", "Prefer reversible actions", "Keep environment boundaries explicit"],
        "benchmarks": ["Can identify project root, runtime, test commands, and active services without editing files"],
    },
    {
        "stage": 1,
        "name": "Code reading",
        "outcome": "Trace existing behavior and ownership before proposing or writing code.",
        "corePrinciples": ["Read call paths", "Find contracts", "Distinguish source truth from presentation", "Respect local conventions"],
        "benchmarks": ["Can explain request flow, data flow, and affected files with line-level evidence"],
    },
    {
        "stage": 2,
        "name": "Scoped fixes",
        "outcome": "Make narrow, maintainable changes that solve the issue without collateral churn.",
        "corePrinciples": ["Small coherent diffs", "Existing patterns first", "Proportional tests", "No unrelated refactors"],
        "benchmarks": ["Can land a bug fix with focused tests and no unrelated file changes"],
    },
    {
        "stage": 3,
        "name": "Testing and debugging",
        "outcome": "Reproduce defects, isolate root causes, prove fixes, and report residual risk.",
        "corePrinciples": ["Reproduce first", "Change one variable at a time", "Verify the failing and passing states", "Keep evidence"],
        "benchmarks": ["Can produce a failing test or repro, implement the fix, and show passing verification"],
    },
    {
        "stage": 4,
        "name": "Backend, API, and data contracts",
        "outcome": "Build stable APIs and data flows with explicit schemas, failure modes, and source attribution.",
        "corePrinciples": ["Contract stability", "Fail closed", "Source-backed data", "Clear status states", "No silent substitutions"],
        "benchmarks": ["Can add an endpoint or data connector with parser tests, endpoint tests, source metadata, and error handling"],
    },
    {
        "stage": 5,
        "name": "Frontend and product execution",
        "outcome": "Ship usable product surfaces with correct state, responsive layout, and browser-verified behavior.",
        "corePrinciples": ["Workflow first", "Real state handling", "Visual QA", "Accessibility basics", "No decorative fake complexity"],
        "benchmarks": ["Can verify a user-facing flow in browser with screenshots or concrete interaction evidence"],
    },
    {
        "stage": 6,
        "name": "DevOps and release",
        "outcome": "Deploy safely with backups, preflight checks, scoped service changes, live validation, logs, and rollback awareness.",
        "corePrinciples": ["Explicit approval", "Predeploy evidence", "Scoped mutation", "Health checks", "Log inspection", "Rollback path"],
        "benchmarks": ["Can deploy one service without recreating unrelated services and produce a complete validation record"],
    },
    {
        "stage": 7,
        "name": "Security and reliability",
        "outcome": "Identify and block unsafe changes across auth, secrets, RBAC, PII, public endpoints, integrations, and infrastructure.",
        "corePrinciples": ["Least privilege", "Secret hygiene", "Trust boundaries", "Auditability", "Fail closed", "Abuse-case thinking"],
        "benchmarks": ["Can name security release blockers and verify public outputs do not leak sensitive data"],
    },
    {
        "stage": 8,
        "name": "Architecture",
        "outcome": "Design systems that remain understandable, observable, evolvable, and safe under change.",
        "corePrinciples": ["Boundaries", "Invariants", "Migration safety", "Observability", "Operational ownership"],
        "benchmarks": ["Can write an architecture plan another senior engineer can execute without hidden assumptions"],
    },
    {
        "stage": 9,
        "name": "Staff-level execution",
        "outcome": "Turn ambiguous goals into shipped, monitored, documented systems while raising team judgment.",
        "corePrinciples": ["Clarify intent", "Sequence risk", "Choose leverage", "Teach through evidence", "Preserve continuity"],
        "benchmarks": ["Can lead a multi-phase effort from strategy through deploy, canary, documentation, and handoff"],
    },
]

STAGE_BY_CLASSIFICATION = {
    "trivial": 1,
    "normal": 2,
    "architecture": 8,
    "product": 9,
    "ui_product": 5,
    "security_compliance": 7,
    "data_financial": 4,
    "production_release": 6,
}

STAGE_TRAINING = {
    0: {
        "learningObjective": "Build safe command-line and project-orientation habits before editing.",
        "expertMentalModel": "Production work starts by knowing where you are, what is running, and what action is reversible.",
        "nextDrill": "Open a new repo and produce a read-only orientation note: root, stack, services, tests, and risks.",
    },
    1: {
        "learningObjective": "Trace behavior from entrypoint to output before changing code.",
        "expertMentalModel": "Senior engineers first locate the contract and invariants; implementation follows from the system shape.",
        "nextDrill": "Pick one endpoint or UI action and write the exact file/function/data-flow chain before editing it.",
    },
    2: {
        "learningObjective": "Make the smallest coherent change that solves the request.",
        "expertMentalModel": "The best fix is often the one that preserves the most existing system behavior.",
        "nextDrill": "Fix a small defect with one focused test and explain why no broader refactor was needed.",
    },
    3: {
        "learningObjective": "Prove a bug exists, prove the fix, and preserve the repro as regression coverage.",
        "expertMentalModel": "A fix without a reproduced failure is a guess; evidence converts guesses into engineering.",
        "nextDrill": "For the next bug, write the failing assertion or command output before touching implementation.",
    },
    4: {
        "learningObjective": "Build APIs and data flows that are explicit about schema, source, freshness, and failure.",
        "expertMentalModel": "Data products fail when missingness and provenance are hidden; production systems make state explicit.",
        "nextDrill": "Add or review one endpoint and list every success, empty, stale, and source-error state it can return.",
    },
    5: {
        "learningObjective": "Deliver user-facing surfaces that work under real states, devices, and interactions.",
        "expertMentalModel": "A UI is not done when it renders; it is done when target users can complete the workflow reliably.",
        "nextDrill": "Verify one workflow in desktop and mobile viewports and capture the exact states tested.",
    },
    6: {
        "learningObjective": "Deploy with scoped blast radius, preflight evidence, live validation, and rollback awareness.",
        "expertMentalModel": "Release engineering is controlled mutation of production, not a final command after coding.",
        "nextDrill": "Write a deploy checklist that names backup, command scope, health checks, logs, and rollback trigger.",
    },
    7: {
        "learningObjective": "Identify security and reliability blockers before they reach production.",
        "expertMentalModel": "Every boundary is a trust decision; production code must make those decisions explicit and testable.",
        "nextDrill": "Threat-model one public endpoint: inputs, auth, secrets, abuse cases, logs, and data exposure.",
    },
    8: {
        "learningObjective": "Design changes around boundaries, invariants, migration safety, and operational ownership.",
        "expertMentalModel": "Architecture is the set of constraints that makes future correct changes easier than incorrect ones.",
        "nextDrill": "Write an architecture note for one upcoming change with invariants, failure modes, tests, and rollback.",
    },
    9: {
        "learningObjective": "Convert ambiguous goals into sequenced, verified, documented, production outcomes.",
        "expertMentalModel": "Staff-level work reduces uncertainty for the whole system and leaves others able to continue.",
        "nextDrill": "Take one vague product request and turn it into phases, acceptance checks, release gates, and a handoff plan.",
    },
}

ANTI_SLOP_BASE = [
    "Do not invent source data, API behavior, file contents, or test results.",
    "Do not claim production readiness without the required gates for the risk class.",
    "Do not hide missing verification; report skipped checks and residual risk.",
    "Do not make broad refactors or metadata churn unrelated to the request.",
    "Do not mutate production, secrets, DNS, data, git history, or deployment state without explicit approval.",
]

ANTI_SLOP_BY_CLASSIFICATION = {
    "architecture": ["Do not change contracts, schemas, or cross-module behavior without an architecture and migration review."],
    "ui_product": ["Do not stop at static rendering; verify real user flows and responsive states."],
    "security_compliance": ["Do not expose secrets, weaken auth, or skip trust-boundary review."],
    "data_financial": ["Do not use stale, unverified, or silently substituted data; include source and freshness state."],
    "production_release": ["Do not deploy without backup/preflight evidence, scoped commands, health checks, logs, and rollback awareness."],
}

REVIEW_RUBRIC_BASE = [
    "Scope: the diff is limited to the requested behavior and follows local conventions.",
    "Correctness: changed behavior is covered by focused tests or concrete runtime evidence.",
    "Failure modes: missing, stale, invalid, or unavailable dependencies fail closed and are visible.",
    "Security: auth, secrets, public outputs, and external boundaries are reviewed where applicable.",
    "Operations: deploy/restart/data mutations are explicit, scoped, validated, and documented.",
]

OPERATOR_SCORE_SCALE = [
    {"score": 0, "label": "Observed only", "meaning": "Can follow the result but cannot yet explain or reproduce the work."},
    {"score": 1, "label": "Guided", "meaning": "Can execute with step-by-step help and recognizes the main risks."},
    {"score": 2, "label": "Competent", "meaning": "Can perform the task with a checklist and explain verification evidence."},
    {"score": 3, "label": "Advanced", "meaning": "Can adapt the workflow to adjacent tasks and catch common failure modes."},
    {"score": 4, "label": "Expert", "meaning": "Can design the workflow, review others, and teach the underlying principles."},
]

AGENT_ROSTER = [
    {
        "id": "lead",
        "name": "Lead Engineer",
        "mode": "orchestrator",
        "responsibility": "Own scope, risk classification, subagent dispatch, implementation decisions, final review, and user handoff.",
        "defaultFor": ["all"],
        "mayEdit": True,
        "requiredEvidence": ["task classification", "source-backed plan", "final checks", "residual risk"],
    },
    {
        "id": "architect",
        "name": "Architect",
        "mode": "specialist",
        "responsibility": "Review architecture, module boundaries, data contracts, migrations, and long-term maintainability.",
        "defaultFor": ["architecture"],
        "mayEdit": False,
        "requiredEvidence": ["affected contracts", "tradeoffs", "migration or compatibility risk"],
    },
    {
        "id": "investigator",
        "name": "Code Investigator",
        "mode": "specialist",
        "responsibility": "Trace current behavior, reproduce bugs, identify root cause, and map relevant files before edits.",
        "defaultFor": ["normal", "architecture"],
        "mayEdit": False,
        "requiredEvidence": ["file references", "behavior trace", "root-cause hypothesis"],
    },
    {
        "id": "builder",
        "name": "Builder",
        "mode": "specialist",
        "responsibility": "Implement a bounded change in an explicitly assigned write scope.",
        "defaultFor": ["normal", "architecture", "ui_product"],
        "mayEdit": True,
        "requiredEvidence": ["files changed", "implementation notes", "local checks"],
    },
    {
        "id": "reviewer",
        "name": "Reviewer",
        "mode": "specialist",
        "responsibility": "Review diffs for bugs, regressions, missing tests, hidden assumptions, and scope creep.",
        "defaultFor": ["normal", "architecture", "security_compliance", "data_financial", "production_release"],
        "mayEdit": False,
        "requiredEvidence": ["findings by severity", "missing verification", "release blockers"],
    },
    {
        "id": "qa",
        "name": "QA Engineer",
        "mode": "specialist",
        "responsibility": "Run or design focused verification, browser checks, regression tests, screenshots, and reproducibility checks.",
        "defaultFor": ["normal", "ui_product", "production_release"],
        "mayEdit": False,
        "requiredEvidence": ["commands run", "results", "screenshots or logs where applicable"],
    },
    {
        "id": "security",
        "name": "Security Engineer",
        "mode": "specialist",
        "responsibility": "Audit secrets, auth, RBAC, PII, public boundaries, webhooks, payments, and production mutation risk.",
        "defaultFor": ["security_compliance", "production_release"],
        "mayEdit": False,
        "requiredEvidence": ["trust boundaries", "secret scan status", "security blockers"],
    },
    {
        "id": "devops",
        "name": "DevOps / Release Engineer",
        "mode": "specialist",
        "responsibility": "Check deployment readiness, environment separation, rollback, monitoring, and canary plans.",
        "defaultFor": ["production_release"],
        "mayEdit": False,
        "requiredEvidence": ["preflight status", "rollback plan", "monitoring plan"],
    },
    {
        "id": "product",
        "name": "Product / UX Reviewer",
        "mode": "specialist",
        "responsibility": "Check user workflow, acceptance criteria, UI quality, accessibility basics, and product fit.",
        "defaultFor": ["product", "ui_product"],
        "mayEdit": False,
        "requiredEvidence": ["user flow", "acceptance criteria", "visual/product risks"],
    },
    {
        "id": "quant",
        "name": "Quant / Backtest Reviewer",
        "mode": "specialist",
        "responsibility": "Review EA/backtest evidence, data provenance, model quality, costs, bias controls, and robustness.",
        "defaultFor": ["data_financial"],
        "mayEdit": False,
        "requiredEvidence": ["data source", "cost model", "sample split", "drawdown stress", "bias review"],
    },
    {
        "id": "docs",
        "name": "Documentation / Handoff Writer",
        "mode": "specialist",
        "responsibility": "Document behavior changes, release notes, decisions, and durable handoff context.",
        "defaultFor": ["production_release", "architecture"],
        "mayEdit": True,
        "requiredEvidence": ["docs updated", "handoff summary", "open questions"],
    },
]

TEAM_DISPATCH_POLICY = {
    "singleAgentDefault": "Use only the Lead Engineer for trivial tasks and most one-file fixes.",
    "dispatchThreshold": "Dispatch specialists when the task is broad, ambiguous, risky, production-facing, security-sensitive, UI-sensitive, or quant/data-sensitive.",
    "defaultMaxSpecialists": 3,
    "fullTeamMaxSpecialists": 10,
    "fullTeamRule": "Full team means complete professional coverage, not uncontrolled concurrency. Dispatch in waves when needed.",
    "aboveMaxRule": "Using more than three specialists requires an explicit lead justification tied to risk, complexity, or disjoint work streams.",
    "accountability": "The Lead Engineer remains accountable for final decisions and must synthesize specialist evidence before editing or handoff.",
    "writeControl": "Only one agent should own a file or module write scope at a time. Review, QA, security, product, and quant specialists are report-only unless explicitly assigned a disjoint write scope.",
    "antiSwarm": [
        "Do not spawn agents just to create activity.",
        "Do not ask multiple agents to solve the same question independently unless comparing approaches is the explicit goal.",
        "Do not allow parallel uncontrolled edits to overlapping files.",
        "Every specialist must return concrete evidence, file references, commands, screenshots, reports, or blockers.",
        "The lead must close the loop with final verification and residual risk.",
    ],
}

TEAM_MODES = {
    "single-lead": {
        "description": "Lead Engineer only. Use for small, low-risk, one-file, or clearly bounded work.",
        "concurrency": "none",
        "defaultWriteRule": "Lead Engineer may edit. No subagents.",
    },
    "smart-subagents": {
        "description": "Lead Engineer plus the right specialist team, normally two or three specialists.",
        "concurrency": "limited",
        "defaultWriteRule": "Specialists are read-only by default. Builder edits only assigned disjoint scope.",
    },
    "full-team": {
        "description": "Full 11-role professional coverage. This is not permission for uncontrolled parallel edits.",
        "concurrency": "wave-based",
        "defaultWriteRule": "One Builder by default. More writers require explicit disjoint file/module ownership.",
    },
}

TEAM_COORDINATION_PROTOCOL = {
    "coreRule": "Full team means complete professional coverage, not uncontrolled concurrency.",
    "coordinationPacketRequiredFor": ["smart-subagents", "full-team"],
    "requiredFields": [
        "goal",
        "riskClass",
        "mode",
        "rolesUsed",
        "rolesNotUsed",
        "readWritePermissions",
        "fileOwnershipMap",
        "capabilityPlan",
        "evidenceContract",
        "conflictRule",
        "stopConditions",
        "verificationGate",
        "handoffGate",
    ],
    "permissionDefaults": {
        "lead": "orchestrator; may edit",
        "builder": "may edit only assigned disjoint scope",
        "docs": "docs only when assigned",
        "allOtherSpecialists": "read-only",
    },
    "fileOwnershipRules": [
        "No two editing agents may own the same file or module.",
        "Shared files require Lead Engineer ownership or explicit serialization.",
        "Specialists may not edit outside assigned write scope.",
        "A file ownership conflict blocks dispatch until resolved.",
        "If the scope cannot be split cleanly, use one Builder.",
    ],
    "evidenceContract": [
        "scope handled",
        "files, commands, screenshots, logs, reports, or data reviewed",
        "findings ordered by severity or importance",
        "explicit blockers",
        "residual risk",
        "recommended next action",
        "session-signed jstack.specialist.result.v1 receipt",
    ],
    "conflictRule": "Evidence beats opinion. Reproduction beats speculation. Project rules beat generic best practice. Safety gates beat speed. Lead Engineer decides and documents unresolved risk.",
    "stopConditions": [
        "required user approval is missing",
        "production deploy/restart/data mutation is implied but not approved",
        "secrets or credentials are exposed",
        "agents disagree on a release blocker",
        "tests fail for an unclear reason",
        "file ownership overlaps",
        "the task scope expands beyond the user request",
        "the strategy or implementation would be misleading without more evidence",
    ],
    "fullTeamWavePattern": [
        "Discovery wave: Architect, Code Investigator, Product/UX or Quant when relevant.",
        "Build wave: Builder only after Lead approves scope.",
        "Review wave: Reviewer, QA, Security, DevOps, Documentation.",
        "Synthesis wave: Lead reconciles evidence, resolves conflicts, verifies, and hands off.",
    ],
}


def workflow_skill_names() -> list[str]:
    names: list[str] = []
    for group in WORKFLOW_PROFILE:
        for skill in group["skills"]:
            if skill not in names:
                names.append(skill)
    return names


def roster_agent(agent_id: str) -> dict[str, Any]:
    return next(agent for agent in AGENT_ROSTER if agent["id"] == agent_id)


def _capability_call(operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except capability_core.CapabilityError as exc:
        raise ToolError(str(exc)) from exc


def specialist_capability_plan(
    goal: str,
    classifications: list[dict[str, Any]],
    selected_ids: list[str],
    explicit_capability_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    return _capability_call(
        lambda: capability_core.select_capabilities(
            goal,
            selected_ids,
            [str(item["id"]) for item in classifications],
            explicit_capability_ids or [],
        )
    )


def capability_assignments_by_role(capability_plan: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        str(assignment["roleId"]): list(assignment.get("capabilities") or [])
        for assignment in capability_plan.get("assignments") or []
    }


def capability_enriched_agents(
    selected_ids: list[str], capability_plan: dict[str, Any]
) -> list[dict[str, Any]]:
    assignments = capability_assignments_by_role(capability_plan)
    agents: list[dict[str, Any]] = []
    for agent_id in selected_ids:
        agent = dict(roster_agent(agent_id))
        role_capabilities = assignments.get(agent_id, [])
        agent["capabilityIds"] = [str(item["capabilityId"]) for item in role_capabilities]
        agent["capabilities"] = role_capabilities
        agent["capabilityCatalogDigest"] = capability_plan["catalogDigest"]
        agent["permissionInvariant"] = capability_plan["permissionInvariant"]
        agents.append(agent)
    return agents


def normalize_team_mode(team_mode: Optional[str]) -> str:
    normalized = (team_mode or "auto").strip().lower().replace("_", "-")
    aliases = {
        "single": "single-lead",
        "single-agent": "single-lead",
        "lead": "single-lead",
        "lead-only": "single-lead",
        "smart": "smart-subagents",
        "subagents": "smart-subagents",
        "right-team": "smart-subagents",
        "full": "full-team",
        "fullteam": "full-team",
        "11": "full-team",
        "11-agent": "full-team",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"auto", "single-lead", "smart-subagents", "full-team"}:
        raise ToolError("team_mode must be one of auto, single-lead, smart-subagents, or full-team.")
    return normalized


def choose_agent_team(
    goal: str,
    classifications: list[dict[str, Any]],
    quality_level: str = "enterprise",
    team_mode: Optional[str] = "auto",
    capability_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    mode_requested = normalize_team_mode(team_mode)
    classification_ids = {item["id"] for item in classifications}
    goal_l = goal.lower()
    selected_ids: list[str] = ["lead"]

    def add(agent_id: str) -> None:
        if agent_id not in selected_ids:
            selected_ids.append(agent_id)

    if mode_requested == "full-team":
        selected_ids = [agent["id"] for agent in AGENT_ROSTER]
        capability_plan = specialist_capability_plan(
            goal, classifications, selected_ids, capability_ids
        )
        agents = capability_enriched_agents(selected_ids, capability_plan)
        return {
            "mode": "full-team",
            "requestedMode": mode_requested,
            "reason": "Full-team mode was explicitly requested; use all 11 roles as professional coverage, dispatching in waves if needed.",
            "dispatchRequired": True,
            "dispatchRequirement": dispatch_requirement_text(True, goal),
            "maxAgents": len(AGENT_ROSTER),
            "specialistCount": len(AGENT_ROSTER) - 1,
            "requiresLeadJustification": False,
            "leadJustification": "Explicit /jstack-full-team invocation or full-team mode request.",
            "agents": agents,
            "capabilityPlan": capability_plan,
            "dispatchPolicy": TEAM_DISPATCH_POLICY,
            "coordinationProtocol": agent_coordination_packet(
                goal, "full-team", selected_ids, classifications, capability_plan
            ),
            "handoffContract": team_handoff_contract(selected_ids, capability_plan),
            "blockedActions": team_blocked_actions(),
        }

    if mode_requested == "single-lead" or (
        mode_requested == "auto" and "trivial" in classification_ids and quality_level == "standard"
    ):
        capability_plan = specialist_capability_plan(
            goal, classifications, ["lead"], capability_ids
        )
        return {
            "mode": "single-agent",
            "requestedMode": mode_requested,
            "reason": "Single-lead mode was requested, or auto mode classified the task as trivial and low risk.",
            "dispatchRequired": False,
            "dispatchRequirement": "No subagent dispatch required for trivial or standard-quality single-agent work.",
            "maxAgents": 1,
            "specialistCount": 0,
            "requiresLeadJustification": False,
            "agents": capability_enriched_agents(["lead"], capability_plan),
            "capabilityPlan": capability_plan,
            "dispatchPolicy": TEAM_DISPATCH_POLICY,
            "coordinationProtocol": agent_coordination_packet(
                goal, "single-lead", ["lead"], classifications, capability_plan
            ),
            "handoffContract": team_handoff_contract(["lead"], capability_plan),
            "blockedActions": team_blocked_actions(),
        }

    specialist_priority: list[str] = []

    def prioritize(*agent_ids: str) -> None:
        for agent_id in agent_ids:
            if agent_id not in specialist_priority:
                specialist_priority.append(agent_id)

    if "production_release" in classification_ids:
        prioritize("devops", "security", "qa")
    if "security_compliance" in classification_ids:
        prioritize("security", "reviewer", "qa")
    if "ui_product" in classification_ids:
        prioritize("product", "qa", "reviewer")
    if "data_financial" in classification_ids:
        prioritize("quant", "reviewer", "qa")
    if "architecture" in classification_ids:
        prioritize("architect", "investigator", "reviewer")
    if "product" in classification_ids:
        prioritize("product", "reviewer", "docs")
    if re.search(r"debug|root cause|failing|broken|crash|regression", goal_l):
        add("investigator")
        add("qa")
    if re.search(r"\bphase\b|\bmilestone\b|\bproject\b|\broad roadmap\b|\broad work\b", goal_l):
        add("investigator")
        add("reviewer")
    if re.search(r"implement|build|code|create|scaffold", goal_l):
        add("builder")
        add("reviewer")
    if re.search(r"readme|docs|documentation|github repo|repository|package", goal_l):
        add("docs")
    if quality_level == "enterprise" and len(selected_ids) == 1:
        add("reviewer")

    if re.search(r"debug|root cause|failing|broken|crash|regression", goal_l):
        prioritize("investigator", "qa", "reviewer")
    if re.search(r"implement|build|code|create|scaffold", goal_l):
        prioritize("builder", "reviewer", "qa")
    if "normal" in classification_ids:
        prioritize("investigator", "reviewer")
    if re.search(r"readme|docs|documentation|github repo|repository|package", goal_l):
        prioritize("docs")
    if not specialist_priority and (mode_requested == "smart-subagents" or quality_level == "enterprise"):
        prioritize("investigator", "reviewer")
    selected_ids = ["lead"] + specialist_priority[: int(TEAM_DISPATCH_POLICY["defaultMaxSpecialists"])]

    capability_plan = specialist_capability_plan(
        goal, classifications, selected_ids, capability_ids
    )
    agents = capability_enriched_agents(selected_ids, capability_plan)
    mode = "single-agent" if selected_ids == ["lead"] else "lead-plus-specialists"
    execution_mode = "single-lead" if selected_ids == ["lead"] else "smart-subagents"
    specialist_count = max(0, len(selected_ids) - 1)
    dispatch_required = should_require_dispatch(goal, classification_ids, specialist_count)
    return {
        "mode": mode,
        "requestedMode": mode_requested,
        "executionMode": execution_mode,
        "reason": "Right-sized team selected from task risk classes; smart mode is capped at three specialists.",
        "dispatchRequired": dispatch_required,
        "dispatchRequirement": dispatch_requirement_text(dispatch_required, goal),
        "maxAgents": 1 + int(TEAM_DISPATCH_POLICY["defaultMaxSpecialists"]),
        "specialistCount": specialist_count,
        "requiresLeadJustification": specialist_count > int(TEAM_DISPATCH_POLICY["defaultMaxSpecialists"]),
        "agents": agents,
        "capabilityPlan": capability_plan,
        "dispatchPolicy": TEAM_DISPATCH_POLICY,
        "coordinationProtocol": agent_coordination_packet(
            goal, execution_mode, selected_ids, classifications, capability_plan
        ),
        "handoffContract": team_handoff_contract(selected_ids, capability_plan),
        "blockedActions": team_blocked_actions(),
    }


def agent_coordination_packet(
    goal: str,
    mode: str,
    selected_ids: list[str],
    classifications: list[dict[str, Any]],
    capability_plan: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if capability_plan is None:
        capability_plan = specialist_capability_plan(
            goal, classifications, selected_ids, []
        )
    capability_assignments = capability_assignments_by_role(capability_plan)
    selected = set(selected_ids)
    roles_used = []
    roles_not_used = []
    for agent in AGENT_ROSTER:
        entry = {
            "id": agent["id"],
            "name": agent["name"],
            "defaultPermission": role_permission(agent["id"]),
            "requiredEvidence": agent["requiredEvidence"],
        }
        if agent["id"] in selected:
            entry["whyNeeded"] = role_selection_reason(agent["id"], classifications, mode)
            entry["capabilities"] = capability_assignments.get(agent["id"], [])
            entry["capabilityIds"] = [
                str(item["capabilityId"])
                for item in capability_assignments.get(agent["id"], [])
            ]
            roles_used.append(entry)
        else:
            entry["whySkipped"] = "Not required for this mode/risk class unless new evidence raises risk."
            roles_not_used.append(entry)
    return {
        "goal": goal,
        "riskClass": [item["id"] for item in classifications],
        "mode": mode,
        "modeDefinition": TEAM_MODES[mode],
        "rolesUsed": roles_used,
        "rolesNotUsed": roles_not_used,
        "readWritePermissions": TEAM_COORDINATION_PROTOCOL["permissionDefaults"],
        "fileOwnershipMapRequired": mode != "single-lead",
        "fileOwnershipRules": TEAM_COORDINATION_PROTOCOL["fileOwnershipRules"],
        "capabilityPlan": capability_plan,
        "evidenceContract": TEAM_COORDINATION_PROTOCOL["evidenceContract"],
        "conflictRule": TEAM_COORDINATION_PROTOCOL["conflictRule"],
        "stopConditions": TEAM_COORDINATION_PROTOCOL["stopConditions"],
        "verificationGate": "Define tests, lint/typecheck/build, browser QA, security scan, backtest evidence, logs, or screenshots required for this risk class.",
        "handoffGate": "Lead must validate session-signed specialist receipts, reconcile findings and conflicts, then summarize changed files, checks, unresolved risks, and next steps.",
        "wavePattern": TEAM_COORDINATION_PROTOCOL["fullTeamWavePattern"] if mode == "full-team" else [],
        "antiSlopStandard": ANTI_SLOP_BASE,
    }


def role_permission(agent_id: str) -> str:
    if agent_id == "lead":
        return "orchestrator; may edit"
    if agent_id == "builder":
        return "may edit only assigned disjoint scope"
    if agent_id == "docs":
        return "docs only when assigned"
    return "read-only"


def role_selection_reason(agent_id: str, classifications: list[dict[str, Any]], mode: str) -> str:
    if agent_id == "lead":
        return "Required for scope ownership, synthesis, final decision, verification, and handoff."
    if mode == "full-team":
        return "Included by explicit full-team mode as professional coverage; may be dispatched in a wave instead of concurrently."
    classification_agents = {
        "normal": {"investigator", "builder", "reviewer", "qa"},
        "architecture": {"architect", "investigator", "reviewer", "docs"},
        "product": {"product", "docs"},
        "ui_product": {"product", "qa", "reviewer"},
        "security_compliance": {"security", "reviewer", "qa"},
        "data_financial": {"quant", "reviewer", "qa"},
        "production_release": {"devops", "security", "qa", "reviewer", "docs"},
    }
    matching = [
        item["label"]
        for item in classifications
        if agent_id in classification_agents.get(item["id"], set())
    ]
    if matching:
        return "Selected by risk classification: " + ", ".join(matching)
    return "Selected because the task risk or goal keywords match this specialist's responsibility."


def should_require_dispatch(goal: str, classification_ids: set[str], specialist_count: int) -> bool:
    goal_l = goal.lower()
    complex_goal = bool(re.search(r"\bphase\b|\bmilestone\b|\bsprint\b|\broad\b|\bproject\b|\bmulti[- ]module\b|\bproduction\b|\bdeploy\b|\brelease\b|\bsecurity\b|\bauth\b|\barchitecture\b|\bdebug\b|\broot cause\b|\bquant\b|\bbacktest\b", goal_l))
    high_risk = bool(classification_ids & {"architecture", "ui_product", "security_compliance", "data_financial", "production_release"})
    return specialist_count > 0 and (complex_goal or high_risk)


def dispatch_requirement_text(required: bool, goal: str) -> str:
    if required:
        return (
            "If multi-agent tools are available, the Lead Engineer must spawn the selected specialists before implementation or final handoff. "
            "If no specialists are spawned, the Lead must explicitly state why dispatch was skipped."
        )
    return "Specialist dispatch is optional; the Lead may stay single-agent if the task remains scoped and low-risk."


def team_handoff_contract(
    agent_ids: list[str], capability_plan: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    assignments = capability_assignments_by_role(capability_plan or {"assignments": []})
    return {
        "leadMustSynthesize": True,
        "specialistResultSchema": "jstack.specialist.result.v1",
        "specialistTelemetrySchema": "jstack.specialist.telemetry.v1",
        "specialistReceiptKind": "specialist-result",
        "capabilityCatalogDigest": (capability_plan or {}).get("catalogDigest"),
        "expectedRoleCapabilities": {
            agent_id: [str(item["capabilityId"]) for item in assignments.get(agent_id, [])]
            for agent_id in agent_ids
        },
        "requiredFromEachSpecialist": [
            "scope handled",
            "evidence gathered",
            "findings or changes",
            "blockers",
            "residual risk",
            "privacy-safe telemetry metadata",
            "session-signed specialist result receipt",
        ],
        "writeOwnership": "Any editing specialist must own a disjoint file/module scope and list changed paths.",
        "finalLeadChecklist": [
            "specialist results reconciled",
            "specialist receipts validated against the current Git state and capability catalog",
            "conflicts resolved",
            "verification run or blockers reported",
            "production claims limited to available evidence",
            "handoff includes changed files, checks, risks, and next steps",
        ],
        "activeAgentIds": agent_ids,
    }


def team_blocked_actions() -> list[str]:
    return [
        "Subagents must not spawn additional subagents.",
        "Subagents must not create repositories, add/change remotes, commit, push, create pull requests, merge, tag, release, deploy, delete data, reset git state, restart production, alter DNS/SSL, or modify production systems.",
        "Only the accountable Lead may request and consume a separate exact JStack external-action authorization; team or phase approval never grants it.",
        "Subagents must not edit files outside their assigned write scope.",
        "Subagents must not claim completion without evidence.",
        "Subagents must not duplicate another specialist's task unless comparison is explicitly requested.",
    ]


def classification_public(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key != "patterns"}


def classify_work(goal: str) -> list[dict[str, Any]]:
    goal_l = goal.lower()
    matched: list[dict[str, Any]] = []
    for classification in WORK_CLASSIFICATIONS:
        if any(re.search(pattern, goal_l) for pattern in classification["patterns"]):
            matched.append(classification_public(classification))
    if not matched:
        matched.append(classification_public(next(item for item in WORK_CLASSIFICATIONS if item["id"] == "normal")))
    if len(matched) > 1:
        matched = [item for item in matched if item["id"] != "trivial"]
    return matched


def choose_skills(goal: str, quality_level: str = "enterprise") -> list[str]:
    goal_l = goal.lower()
    selected: list[str] = []
    classifications = classify_work(goal)

    def add(skill: str) -> None:
        if skill not in selected:
            selected.append(skill)

    for classification in classifications:
        for skill in classification.get("skills", []):
            add(skill)

    rules = [
        ("spec|requirements|scope|acceptance", "spec"),
        ("autoplan|whole plan|parallel plan|full plan|broad|multi-step", "autoplan"),
        ("ceo|product|business|strategy|positioning", "plan-ceo-review"),
        ("office hours|customer|persona|pricing|market|demand", "office-hours"),
        ("architecture|schema|database|migration|api|integration|refactor", "plan-eng-review"),
        ("developer experience|docs|sdk|cli|onboarding", "plan-devex-review"),
        ("bug|error|broken|debug|root cause|login", "investigate"),
        ("security|audit|csrf|xss|secret|credential|compliance|auth|rbac|payment|pii|webhook", "cso"),
        ("destructive|dangerous|reset|delete|force", "careful"),
        ("guard|boundary|restricted", "guard"),
        ("freeze|only edit|scope edits", "freeze"),
        ("qa|test|verify|does this work|smoke", "qa"),
        ("review|pr|diff|code quality", "review"),
        ("health|lint|typecheck|quality", "health"),
        ("design|ui|ux|visual|layout|responsive", "design-review"),
        ("brand|product design|design system", "design-consultation"),
        ("browser|click|screenshot|local app", "browse"),
        ("benchmark|performance|slow|core web vitals", "benchmark"),
        ("ship|deploy|release|pr", "ship"),
        ("canary|monitor|post-deploy", "canary"),
        ("land|merge|deploy", "land-and-deploy"),
        ("document|docs|readme|changelog", "document-release"),
        ("context|resume|handoff|save", "context-save"),
        ("restore|continue|pick up", "context-restore"),
    ]
    for pattern, skill in rules:
        if re.search(pattern, goal_l):
            add(skill)
    if not selected:
        selected = ["spec", "plan-eng-review", "health", "review", "qa", "context-save"]
    limit = 6 if quality_level == "standard" else 12
    return selected[:limit]


def choose_mastery_stage(goal: str, classifications: list[dict[str, Any]]) -> int:
    goal_l = goal.lower()
    if re.search(r"debug|root cause|repro|broken|failing|failure", goal_l):
        return 3
    domain_map = load_mastery_curriculum()["domainStageMap"]
    stages = [int(domain_map.get(item["id"], 2)) for item in classifications]
    return max(stages) if stages else 2


def task_anti_slop_checklist(classifications: list[dict[str, Any]]) -> list[str]:
    checklist = list(ANTI_SLOP_BASE)
    for classification in classifications:
        for item in ANTI_SLOP_BY_CLASSIFICATION.get(classification["id"], []):
            if item not in checklist:
                checklist.append(item)
    return checklist


MASTERY_TRACKS = {"engineering", "audit", "loop"}


def normalize_mastery_track(value: Any = None) -> str:
    track = str(value or "engineering").strip().lower()
    if track not in MASTERY_TRACKS:
        raise ToolError("track must be engineering, audit, or loop.")
    return track


def curriculum_candidates(track: str = "engineering") -> list[Path]:
    track = normalize_mastery_track(track)
    server_dir = Path(__file__).resolve().parent
    filename = {
        "engineering": "curriculum.v1.json",
        "audit": "audit-curriculum.v1.json",
        "loop": "loop-curriculum.v1.json",
    }[track]
    env_name = {
        "engineering": "JSTACK_CURRICULUM",
        "audit": "JSTACK_AUDIT_CURRICULUM",
        "loop": "JSTACK_LOOP_CURRICULUM",
    }[track]
    candidates = [
        Path(os.environ[env_name]).expanduser() if os.environ.get(env_name) else None,
        server_dir / "mastery" / filename,
        server_dir.parent / "mastery" / filename,
        server_dir.parents[1] / "mastery" / filename,
    ]
    return [path.resolve() for path in candidates if path is not None]


def load_mastery_curriculum(track: str = "engineering") -> dict[str, Any]:
    track = normalize_mastery_track(track)
    expected_schema = {
        "engineering": "jstack.mastery.curriculum.v1",
        "audit": "jstack.audit.mastery.curriculum.v1",
        "loop": "jstack.loop.mastery.curriculum.v1",
    }[track]
    for path in curriculum_candidates(track):
        if not path.exists():
            continue
        curriculum = read_json(path)
        if not curriculum or curriculum.get("schemaVersion") != expected_schema:
            raise ToolError(f"Invalid JStack mastery curriculum: {path}")
        stages = curriculum.get("stages")
        if not isinstance(stages, list) or [item.get("stage") for item in stages if isinstance(item, dict)] != list(range(10)):
            raise ToolError(f"JStack mastery curriculum must define ordered stages 0 through 9: {path}")
        if track == "engineering" and not isinstance(curriculum.get("domainStageMap"), dict):
            raise ToolError(f"JStack mastery curriculum is missing domainStageMap: {path}")
        curriculum["_sourcePath"] = str(path)
        return curriculum
    raise ToolError(f"JStack {track} mastery curriculum is missing. Reinstall JStack from a complete package.")


def mastery_curriculum_digest(curriculum: dict[str, Any]) -> str:
    public = {key: value for key, value in curriculum.items() if not key.startswith("_")}
    return hashlib.sha256(
        json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def mastery_profile_path() -> Path:
    return Path.home() / ".jstack" / "mastery" / "profile.json"


def default_mastery_track() -> dict[str, Any]:
    return {
        "currentStage": 0,
        "completedStages": [],
        "attempts": [],
    }


def default_mastery_profile() -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.mastery.profile.v3",
        "createdAt": None,
        "updatedAt": None,
        "learnerName": "Jay",
        "activeTrack": "engineering",
        "tracks": {
            "engineering": default_mastery_track(),
            "audit": default_mastery_track(),
            "loop": default_mastery_track(),
        },
    }


def migrate_mastery_profile(profile: dict[str, Any]) -> dict[str, Any]:
    schema = profile.get("schemaVersion")
    if schema == "jstack.mastery.profile.v3":
        return profile
    if schema not in {"jstack.mastery.profile.v1", "jstack.mastery.profile.v2"}:
        raise ToolError(f"Unsupported JStack mastery profile schema: {schema!r}")
    migrated = default_mastery_profile()
    migrated["createdAt"] = profile.get("createdAt")
    migrated["updatedAt"] = now_iso()
    migrated["learnerName"] = str(profile.get("learnerName") or "Jay")
    if schema == "jstack.mastery.profile.v1":
        migrated["tracks"]["engineering"] = {
            "currentStage": int(profile.get("currentStage", 0)),
            "completedStages": list(profile.get("completedStages") or []),
            "attempts": list(profile.get("attempts") or []),
        }
    else:
        tracks = profile.get("tracks")
        if not isinstance(tracks, dict):
            raise ToolError("Malformed JStack mastery profile v2 tracks.")
        for track in ("engineering", "audit"):
            state = tracks.get(track)
            if not isinstance(state, dict):
                raise ToolError(f"Malformed JStack mastery profile v2 track: {track}")
            migrated["tracks"][track] = json.loads(json.dumps(state))
        active = str(profile.get("activeTrack") or "engineering")
        migrated["activeTrack"] = active if active in {"engineering", "audit"} else "engineering"
    migrated["migration"] = {
        "fromSchema": schema,
        "migratedAt": migrated["updatedAt"],
    }
    return migrated


def load_mastery_profile() -> dict[str, Any]:
    path = mastery_profile_path()
    if not path.exists():
        return default_mastery_profile()
    profile = read_json(path)
    if not profile:
        raise ToolError(f"Invalid JStack mastery profile: {path}")
    if profile.get("schemaVersion") in {
        "jstack.mastery.profile.v1",
        "jstack.mastery.profile.v2",
    }:
        profile = migrate_mastery_profile(profile)
        atomic_write_json(path, profile)
    if profile.get("schemaVersion") != "jstack.mastery.profile.v3":
        raise ToolError(f"Invalid JStack mastery profile: {path}")
    tracks = profile.get("tracks")
    if not isinstance(tracks, dict) or set(tracks) != MASTERY_TRACKS:
        raise ToolError(f"Malformed JStack mastery profile: {path}")
    for track in MASTERY_TRACKS:
        state = tracks.get(track)
        if not isinstance(state, dict) or not isinstance(state.get("attempts"), list) or not isinstance(state.get("currentStage"), int):
            raise ToolError(f"Malformed JStack mastery profile track '{track}': {path}")
    normalize_mastery_track(profile.get("activeTrack"))
    return profile


def mastery_track_state(profile: dict[str, Any], track: str) -> dict[str, Any]:
    return profile["tracks"][normalize_mastery_track(track)]


def curriculum_stage(stage_number: int, track: str = "engineering") -> dict[str, Any]:
    curriculum = load_mastery_curriculum(track)
    return next(stage for stage in curriculum["stages"] if stage["stage"] == stage_number)


def advancement_status(profile: dict[str, Any], stage_number: int, track: str = "engineering") -> dict[str, Any]:
    track = normalize_mastery_track(track)
    state = mastery_track_state(profile, track)
    attempts = [item for item in state.get("attempts", []) if item.get("stage") == stage_number]
    eligible = [
        item
        for item in attempts
        if item.get("eligibleForAdvancement") is True
        and item.get("assistanceLevel") in {"independent", "independent_teach"}
    ]
    if stage_number <= 3:
        recent = attempts[-2:]
        passed = len(recent) == 2 and all(item in eligible and item.get("score", 0) >= 80 for item in recent)
        requirement = "Two consecutive independent attempts scoring at least 80."
    elif stage_number <= 8:
        recent = eligible[-3:]
        scores = [float(item.get("score", 0)) for item in recent]
        work_types = {item.get("exerciseType") for item in recent}
        commits = {item.get("projectState", {}).get("gitHead") for item in recent}
        passed = (
            len(recent) == 3
            and min(scores, default=0) >= 80
            and sum(scores) / len(scores) >= 85
            and {"implementation", "audit"}.issubset(work_types)
            and len(commits) >= 2
        )
        requirement = "Three independent attempts across two commits, each at least 80 and mean at least 85, including implementation and audit."
    else:
        recent = eligible[-2:]
        base_passed = (
            len(recent) == 2
            and all(item.get("score", 0) >= 90 and item.get("blindCapstone") is True for item in recent)
        )
        if track in {"audit", "loop"}:
            challenge_digests = {
                item.get("capstoneAttestation", {}).get("challengeDigest") for item in recent
            }
            passed = (
                base_passed
                and all(
                    item.get("capstoneAttestation", {}).get("valid") is True
                    for item in recent
                )
                and None not in challenge_digests
                and len(challenge_digests) == 2
            )
            requirement = (
                "Two independently attested blind capstones on distinct challenge subjects, "
                "each scoring at least 90 with all capstone hard gates satisfied."
            )
        else:
            passed = base_passed
            requirement = "Two independent blind capstones scoring at least 90 with all capstone hard gates satisfied."
    return {
        "passed": passed,
        "requirement": requirement,
        "attemptCount": len(attempts),
        "eligibleAttemptCount": len(eligible),
    }


def build_task_training(
    goal: str, classifications: list[dict[str, Any]], required_gates: list[str], learning_mode: str
) -> dict[str, Any]:
    profile = load_mastery_profile()
    engineering = mastery_track_state(profile, "engineering")
    learner_stage_number = max(0, min(9, int(engineering.get("currentStage", 0))))
    task_domain_stage_number = choose_mastery_stage(goal, classifications)
    stage = curriculum_stage(learner_stage_number, "engineering")
    first_drill = stage.get("drills", [{}])[0]
    guidance = {
        "learningObjective": stage["outcome"],
        "expertMentalModel": "; ".join(stage.get("corePrinciples", [])),
        "nextDrill": first_drill.get("name"),
    }
    classification_labels = [item["label"] for item in classifications]
    benchmarks = list(stage["benchmarks"])
    if "quality" in required_gates:
        benchmarks.append("Can show exact checks run and explain what each check proves.")
    if "security-compliance" in required_gates:
        benchmarks.append("Can identify trust boundaries, secret exposure risk, and public-output leakage risk.")
    if "release" in required_gates:
        benchmarks.append("Can produce predeploy, deploy, postdeploy, log, and rollback evidence.")
    return {
        "masteryStage": stage,
        "learnerStage": learner_stage_number,
        "taskDomainStage": task_domain_stage_number,
        "learningMode": learning_mode,
        "riskClasses": classification_labels,
        "learningObjective": guidance["learningObjective"],
        "expertMentalModel": guidance["expertMentalModel"],
        "skillBenchmarks": benchmarks,
        "antiSlopChecklist": task_anti_slop_checklist(classifications),
        "reviewRubric": REVIEW_RUBRIC_BASE,
        "nextDrill": guidance["nextDrill"],
        "operatorScorePolicy": {
            "scale": OPERATOR_SCORE_SCALE,
            "rule": "Score only from observed evidence after the task: orientation, implementation, verification, review judgment, and ability to explain the tradeoffs.",
        },
        "masteryTrack": "engineering",
        "advancement": advancement_status(profile, learner_stage_number, "engineering"),
        "instructionContract": {
            "embedded": "After the engineering result, include at most one mental model, one decision checkpoint, and one next drill in three lines.",
            "coach": "Explain decisions interactively while preserving the full engineering gates.",
            "assessment": "Do not provide hidden answers before the attempt; assess only submitted evidence.",
            "off": "Run the enterprise workflow without visible teaching content.",
        }[learning_mode],
    }


def mastery_system() -> dict[str, Any]:
    curriculum = load_mastery_curriculum("engineering")
    audit_curriculum = load_mastery_curriculum("audit")
    loop_curriculum = load_mastery_curriculum("loop")
    return {
        "standard": "Enterprise professional development: evidence-driven, source-backed, production-safe, and designed to train Jay from operator fundamentals to staff-level execution.",
        "schemaVersion": curriculum["schemaVersion"],
        "sourcePath": curriculum["_sourcePath"],
        "stages": curriculum["stages"],
        "advancementPolicy": curriculum["advancementPolicy"],
        "scoring": curriculum["scoring"],
        "operatorScoreScale": OPERATOR_SCORE_SCALE,
        "antiSlopBase": ANTI_SLOP_BASE,
        "tracks": {
            "engineering": {
                "schemaVersion": curriculum["schemaVersion"],
                "sourcePath": curriculum["_sourcePath"],
                "digest": mastery_curriculum_digest(curriculum),
            },
            "audit": {
                "schemaVersion": audit_curriculum["schemaVersion"],
                "sourcePath": audit_curriculum["_sourcePath"],
                "digest": mastery_curriculum_digest(audit_curriculum),
            },
            "loop": {
                "schemaVersion": loop_curriculum["schemaVersion"],
                "sourcePath": loop_curriculum["_sourcePath"],
                "digest": mastery_curriculum_digest(loop_curriculum),
            },
        },
    }


def tool_mastery_status(args: dict[str, Any]) -> dict[str, Any]:
    track = normalize_mastery_track(args.get("track"))
    profile = load_mastery_profile()
    state = mastery_track_state(profile, track)
    current = max(0, min(9, int(state.get("currentStage", 0))))
    curriculum = load_mastery_curriculum(track)
    stage = next(item for item in curriculum["stages"] if item["stage"] == current)
    return {
        "initialized": mastery_profile_path().exists(),
        "profilePath": str(mastery_profile_path()),
        "profileSchemaVersion": profile["schemaVersion"],
        "activeTrack": profile["activeTrack"],
        "track": track,
        "currentStage": stage,
        "completedStages": state.get("completedStages", []),
        "attemptCount": len(state.get("attempts", [])),
        "advancement": advancement_status(profile, current, track),
        "nextDrill": stage["drills"][0] if stage.get("drills") else None,
        "curriculumSource": curriculum["_sourcePath"],
        "curriculumDigest": mastery_curriculum_digest(curriculum),
        "recordType": "Local deliberate-practice record; it is not an external credential or certification.",
    }


def tool_mastery_start(args: dict[str, Any]) -> dict[str, Any]:
    track = normalize_mastery_track(args.get("track"))
    path = mastery_profile_path()
    if path.exists():
        profile = load_mastery_profile()
        if profile["activeTrack"] != track:
            profile["activeTrack"] = track
            profile["updatedAt"] = now_iso()
            atomic_write_json(path, profile)
        return {"created": False, "status": tool_mastery_status({"track": track})}
    profile = default_mastery_profile()
    profile["createdAt"] = now_iso()
    profile["updatedAt"] = profile["createdAt"]
    profile["learnerName"] = str(args.get("learner_name") or "Jay").strip() or "Jay"
    profile["activeTrack"] = track
    atomic_write_json(path, profile)
    return {"created": True, "status": tool_mastery_status({"track": track})}


def hash_mastery_artifact(project_path: Path, raw_path: str) -> dict[str, Any]:
    project_path = project_path.resolve()
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = project_path / candidate
    if candidate.is_symlink():
        raise ToolError(f"Mastery artifact may not be a symlink: {raw_path}")
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(project_path).as_posix()
    except ValueError as exc:
        raise ToolError(f"Mastery artifact must be inside the project: {raw_path}") from exc
    expected_file = resolved.is_file()
    try:
        inventory = audit_core.inventory_repository(
            project_path,
            [relative],
            max_files=1000,
            max_bytes=10_000_000 if expected_file else 20_000_000,
            max_seconds=30,
        )
    except audit_core.AuditError as exc:
        raise ToolError(f"Mastery artifact could not be inventoried safely: {raw_path}") from exc
    if inventory.get("complete") is not True:
        raise ToolError(f"Mastery artifact is unreadable, unsafe, or exceeds its limits: {raw_path}")
    files = inventory.get("files") or []
    if not files:
        raise ToolError(f"Mastery artifact directory is empty: {raw_path}")
    exact = len(files) == 1 and files[0].get("path") == relative
    kind = "file" if exact else "directory"
    total = int(inventory.get("totalBytes") or 0)
    if kind == "file" and total > 10_000_000:
        raise ToolError(f"Mastery artifact exceeds 10 MB: {raw_path}")
    if kind == "file":
        digest_value = str(files[0]["sha256"])
    else:
        digest = hashlib.sha256()
        for item in files:
            nested = str(item["path"])
            prefix = relative.rstrip("/") + "/"
            if not nested.startswith(prefix):
                raise ToolError(f"Mastery artifact inventory escaped its directory: {raw_path}")
            digest.update(nested[len(prefix) :].encode("utf-8"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(str(item["sha256"])))
        digest_value = digest.hexdigest()
    return {"path": relative, "kind": kind, "sha256": digest_value, "bytes": total}


def load_mastery_json_artifact(project_path: Path, artifact: dict[str, Any]) -> dict[str, Any]:
    if artifact.get("kind") != "file":
        raise ToolError("Mastery benchmark evaluation must be a regular JSON file.")
    relative = str(artifact.get("path") or "")
    try:
        content = audit_core.read_repository_file(
            project_path,
            relative,
            max_bytes=10_000_000,
            max_seconds=30,
        )
    except audit_core.AuditError as exc:
        raise ToolError("Mastery benchmark evaluation could not be read safely.") from exc
    if (
        len(content) != artifact.get("bytes")
        or hashlib.sha256(content).hexdigest() != artifact.get("sha256")
    ):
        raise ToolError("Mastery benchmark evaluation changed after artifact hashing.")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ToolError("Mastery benchmark evaluation contains a duplicate JSON key.")
            value[key] = item
        return value

    try:
        parsed = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ToolError("Mastery benchmark evaluation must be valid UTF-8 JSON.") from exc
    if not isinstance(parsed, dict):
        raise ToolError("Mastery benchmark evaluation must contain a JSON object.")
    return parsed


def score_level(score: float) -> int:
    if score < 50:
        return 0
    if score < 65:
        return 1
    if score < 80:
        return 2
    if score < 90:
        return 3
    return 4


def mastery_attempt_evidence_digest(
    track: str,
    stage_number: int,
    drill_id: str,
    assistance: str,
    assessor: str,
    citations: list[str],
    component_scores: dict[str, float],
    artifacts: dict[str, dict[str, Any]],
    state: dict[str, Any],
    benchmark_evaluation: Optional[dict[str, Any]],
) -> str:
    return audit_json_digest(
        {
            "track": track,
            "stage": stage_number,
            "drillId": drill_id,
            "assistanceLevel": assistance,
            "assessor": assessor,
            "assessorCitations": citations,
            "assessment": component_scores,
            "artifacts": artifacts,
            "projectState": {
                "gitRoot": state.get("gitRoot"),
                "gitHead": state.get("gitHead"),
                "projectFingerprint": state.get("projectFingerprint"),
            },
            "benchmarkEvaluationDigest": (
                benchmark_evaluation.get("evaluationDigest")
                if benchmark_evaluation is not None
                else None
            ),
        }
    )


def verify_capstone_attestation(
    raw_attestation: Any,
    expected_assessor: str,
    expected_attempt_digest: str,
    expected_evaluation_digest: str,
    *,
    expected_schema: str,
    assessor_key_env: str,
) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "assessorId",
        "challengeId",
        "challengeDigest",
        "attemptEvidenceDigest",
        "evaluationDigest",
        "issuedAt",
        "expiresAt",
        "blind",
        "independent",
        "signature",
    }
    if not isinstance(raw_attestation, dict) or set(raw_attestation) != required:
        return {"valid": False, "reason": "malformed"}
    body = {key: raw_attestation[key] for key in sorted(required - {"signature"})}
    signature = str(raw_attestation.get("signature") or "")
    key_value = os.environ.get(assessor_key_env, "")
    checks: dict[str, bool] = {
        "schema": body.get("schemaVersion") == expected_schema,
        "assessor": body.get("assessorId") == expected_assessor,
        "challengeId": bool(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", str(body.get("challengeId") or ""))
        ),
        "challengeDigest": bool(
            re.fullmatch(r"sha256:[0-9a-f]{64}", str(body.get("challengeDigest") or ""))
        ),
        "attemptEvidenceDigest": body.get("attemptEvidenceDigest") == expected_attempt_digest,
        "evaluationDigest": body.get("evaluationDigest") == expected_evaluation_digest,
        "blind": body.get("blind") is True,
        "independent": body.get("independent") is True,
        "keyConfigured": len(key_value.encode("utf-8")) >= 32,
        "signatureFormat": bool(re.fullmatch(r"sha256:[0-9a-f]{64}", signature)),
    }
    try:
        issued = _dt.datetime.fromisoformat(str(body["issuedAt"]).replace("Z", "+00:00"))
        expires = _dt.datetime.fromisoformat(str(body["expiresAt"]).replace("Z", "+00:00"))
        if issued.tzinfo is None or expires.tzinfo is None:
            raise ValueError("timezone required")
        issued = issued.astimezone(_dt.timezone.utc)
        expires = expires.astimezone(_dt.timezone.utc)
        now = _dt.datetime.now(_dt.timezone.utc)
        checks["timeWindow"] = (
            issued <= now < expires
            and 0 < (expires - issued).total_seconds()
            <= AUDIT_CAPSTONE_ATTESTATION_MAX_AGE_SECONDS
        )
    except (KeyError, TypeError, ValueError):
        checks["timeWindow"] = False
    if checks["keyConfigured"] and checks["signatureFormat"]:
        message = json.dumps(
            body,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_signature = "sha256:" + hmac.new(
            key_value.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()
        checks["signature"] = hmac.compare_digest(signature, expected_signature)
    else:
        checks["signature"] = False
    valid = all(checks.values())
    return {
        "valid": valid,
        "reason": "verified" if valid else "attestation-check-failed",
        "schemaVersion": body.get("schemaVersion"),
        "assessorId": body.get("assessorId"),
        "challengeId": body.get("challengeId"),
        "challengeDigest": body.get("challengeDigest"),
        "attemptEvidenceDigest": body.get("attemptEvidenceDigest"),
        "evaluationDigest": body.get("evaluationDigest"),
        "issuedAt": body.get("issuedAt"),
        "expiresAt": body.get("expiresAt"),
        "blind": body.get("blind") is True,
        "independent": body.get("independent") is True,
        "attestationDigest": audit_json_digest(body),
        "checks": checks,
    }


def verify_audit_capstone_attestation(
    raw_attestation: Any,
    expected_assessor: str,
    expected_attempt_digest: str,
    expected_evaluation_digest: str,
) -> dict[str, Any]:
    return verify_capstone_attestation(
        raw_attestation,
        expected_assessor,
        expected_attempt_digest,
        expected_evaluation_digest,
        expected_schema=AUDIT_CAPSTONE_ATTESTATION_SCHEMA,
        assessor_key_env=AUDIT_CAPSTONE_ASSESSOR_KEY_ENV,
    )


def verify_loop_capstone_attestation(
    raw_attestation: Any,
    expected_assessor: str,
    expected_attempt_digest: str,
    expected_evaluation_digest: str,
) -> dict[str, Any]:
    return verify_capstone_attestation(
        raw_attestation,
        expected_assessor,
        expected_attempt_digest,
        expected_evaluation_digest,
        expected_schema=LOOP_CAPSTONE_ATTESTATION_SCHEMA,
        assessor_key_env=LOOP_CAPSTONE_ASSESSOR_KEY_ENV,
    )


def evaluate_loop_capstone(raw: Any) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "p0Total",
        "p0Found",
        "p1Total",
        "p1Found",
        "continuationDecisionCorrect",
        "releaseDecisionCorrect",
        "recoveryVerified",
        "evidenceComplete",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise ToolError(
            "Loop Stage 9 capstone-evaluation.json has unsupported or missing fields."
        )
    if raw.get("schemaVersion") != "jstack.loop.capstone-evaluation.v1":
        raise ToolError("Loop Stage 9 capstone evaluation schema is unsupported.")
    metrics: dict[str, Any] = {"schemaVersion": raw["schemaVersion"]}
    for field in ("p0Total", "p0Found", "p1Total", "p1Found"):
        value = raw.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ToolError(f"Loop Stage 9 capstone evaluation {field} must be a non-negative integer.")
        metrics[field] = value
    if metrics["p0Found"] > metrics["p0Total"] or metrics["p1Found"] > metrics["p1Total"]:
        raise ToolError("Loop Stage 9 capstone findings found cannot exceed seeded totals.")
    for field in (
        "continuationDecisionCorrect",
        "releaseDecisionCorrect",
        "recoveryVerified",
        "evidenceComplete",
    ):
        if not isinstance(raw.get(field), bool):
            raise ToolError(f"Loop Stage 9 capstone evaluation {field} must be a boolean.")
        metrics[field] = raw[field]
    return {**metrics, "evaluationDigest": audit_json_digest(metrics)}


def tool_mastery_record(args: dict[str, Any]) -> dict[str, Any]:
    if not mastery_profile_path().exists():
        raise ToolError("Start the mastery system with jstack_mastery_start before recording an attempt.")
    project_path = require_project_path(args.get("project_path"))
    track = normalize_mastery_track(args.get("track"))
    profile = load_mastery_profile()
    track_state = mastery_track_state(profile, track)
    stage_number = int(args.get("stage", -1))
    if stage_number != track_state["currentStage"]:
        raise ToolError(f"Attempt stage must match current {track} learner stage {track_state['currentStage']}.")
    stage = curriculum_stage(stage_number, track)
    drill_id = str(args.get("drill_id") or "").strip()
    drill = next((item for item in stage.get("drills", []) if item.get("id") == drill_id), None)
    if not drill:
        raise ToolError(f"Unknown drill_id for stage {stage_number}: {drill_id}")
    assistance = str(args.get("assistance_level") or "").strip()
    curriculum = load_mastery_curriculum(track)
    caps = curriculum["scoring"]["assistanceCaps"]
    if assistance not in caps:
        raise ToolError("assistance_level must be observed, guided, checklist, independent, or independent_teach.")
    assessor = str(args.get("assessor") or "").strip()
    citations = args.get("assessor_citations") or []
    if not assessor or not isinstance(citations, list) or not all(isinstance(item, str) and item.strip() for item in citations):
        raise ToolError("assessor and at least one assessor_citation are required.")
    assessment = args.get("assessment") or {}
    weights = curriculum["scoring"]["weights"]
    if not isinstance(assessment, dict):
        raise ToolError("assessment must be an object with the five rubric scores.")
    component_scores: dict[str, float] = {}
    for component in weights:
        try:
            value = float(assessment[component])
        except (KeyError, TypeError, ValueError) as exc:
            raise ToolError(f"assessment.{component} must be a number from 0 to 100.") from exc
        if not 0 <= value <= 100:
            raise ToolError(f"assessment.{component} must be between 0 and 100.")
        component_scores[component] = value
    score = round(sum(component_scores[key] * float(weight) / 100 for key, weight in weights.items()), 2)
    raw_level = score_level(score)
    demonstrated_level = min(raw_level, int(caps[assistance]))

    artifacts_arg = args.get("artifacts") or {}
    if not isinstance(artifacts_arg, dict):
        raise ToolError("artifacts must map each required artifact name to a project-relative path.")
    missing_artifacts = [name for name in stage.get("requiredArtifacts", []) if not artifacts_arg.get(name)]
    if missing_artifacts:
        raise ToolError("Missing required mastery artifacts: " + ", ".join(missing_artifacts))
    artifacts = {
        requirement: hash_mastery_artifact(project_path, str(artifacts_arg[requirement]))
        for requirement in stage.get("requiredArtifacts", [])
    }
    benchmark_evaluation = None
    loop_capstone_evaluation = None
    if track == "audit" and stage_number == 9:
        if args.get("capstone_results") not in (None, {}):
            raise ToolError(
                "Audit Stage 9 does not accept caller-supplied aggregate capstone_results; "
                "metrics are derived from the evaluation-results.json benchmark submissions."
            )
        evaluation = load_mastery_json_artifact(
            project_path,
            artifacts["evaluation-results.json"],
        )
        try:
            benchmark_evaluation = audit_core.score_benchmark_evaluation(evaluation)
        except audit_core.AuditError as exc:
            raise ToolError(f"Audit Stage 9 benchmark evaluation is invalid: {exc}") from exc
    elif track == "loop" and stage_number == 9:
        if args.get("capstone_results") not in (None, {}):
            raise ToolError(
                "Loop Stage 9 does not accept caller-supplied capstone_results; "
                "metrics come from the hashed capstone-evaluation.json artifact."
            )
        evaluation = load_mastery_json_artifact(
            project_path,
            artifacts["capstone-evaluation.json"],
        )
        loop_capstone_evaluation = evaluate_loop_capstone(evaluation)

    state = project_state(project_path)
    capstone_attestation = None
    if track == "audit" and stage_number == 9:
        assert benchmark_evaluation is not None
        attempt_digest = mastery_attempt_evidence_digest(
            track,
            stage_number,
            drill_id,
            assistance,
            assessor,
            citations,
            component_scores,
            artifacts,
            state,
            benchmark_evaluation,
        )
        capstone_attestation = verify_audit_capstone_attestation(
            args.get("assessor_attestation"),
            assessor,
            attempt_digest,
            str(benchmark_evaluation["evaluationDigest"]),
        )
    elif track == "loop" and stage_number == 9:
        assert loop_capstone_evaluation is not None
        attempt_digest = mastery_attempt_evidence_digest(
            track,
            stage_number,
            drill_id,
            assistance,
            assessor,
            citations,
            component_scores,
            artifacts,
            state,
            loop_capstone_evaluation,
        )
        capstone_attestation = verify_loop_capstone_attestation(
            args.get("assessor_attestation"),
            assessor,
            attempt_digest,
            str(loop_capstone_evaluation["evaluationDigest"]),
        )
    hard_blocks = [str(item) for item in (args.get("hard_gate_failures") or []) if str(item).strip()]
    if stage_number == 0:
        artifact_paths = [item["path"] for item in artifacts.values()]
        if any(not path.startswith(".jstack-training/") for path in artifact_paths):
            hard_blocks.append("Stage 0 artifacts must live under .jstack-training/.")
        disallowed_changes = [
            path for path in git_changed_files(project_path) if not path.startswith(".jstack-training/")
        ]
        if disallowed_changes:
            hard_blocks.append(
                "Stage 0 project state contains non-training changes: " + ", ".join(disallowed_changes)
            )
    if stage_number >= 2 and not state["clean"]:
        hard_blocks.append("Stage 2+ evidence must be recorded from a clean committed project state.")
    qa_receipts = args.get("qa_receipts") or []
    if not isinstance(qa_receipts, list) or not all(isinstance(item, str) for item in qa_receipts):
        raise ToolError("qa_receipts must be an array.")
    qa_verifications = [verify_receipt(receipt, "qa", state) for receipt in qa_receipts]
    valid_qa = [item for item in qa_verifications if item["valid"]]
    if stage_number >= 2 and not valid_qa:
        hard_blocks.append("Stage 2+ attempt requires a current passing QA evidence receipt.")
    if stage_number >= 6:
        valid_keys = {item["payload"].get("commandKey") for item in valid_qa}
        missing_checks = [item["key"] for item in discover_test_commands(project_path) if item["key"] not in valid_keys]
        if missing_checks:
            hard_blocks.append("Stage 6+ attempt is missing QA receipts for: " + ", ".join(missing_checks))
    security_verification = None
    if stage_number >= 7:
        security_receipt = str(args.get("security_receipt") or "").strip()
        if not security_receipt:
            hard_blocks.append("Stage 7+ attempt requires a current complete security receipt.")
        else:
            security_verification = verify_receipt(security_receipt, "security", state)
            if not security_verification["valid"]:
                hard_blocks.append("Stage 7+ security receipt is invalid or stale.")
    audit_verification = None
    if track == "audit" and stage_number >= 8:
        audit_receipt = str(args.get("audit_receipt") or "").strip()
        if not audit_receipt:
            hard_blocks.append("Audit Stage 8+ attempt requires a current complete audit receipt.")
        else:
            audit_verification = verify_receipt(
                audit_receipt,
                "audit",
                state,
                require_passed=False,
            )
            payload = audit_verification.get("payload") or {}
            if (
                not audit_verification["valid"]
                or payload.get("complete") is not True
                or payload.get("resultStatus") not in {"pass", "fail"}
            ):
                hard_blocks.append("Audit Stage 8+ receipt is invalid, stale, or incomplete.")
    elif track == "loop" and stage_number >= 8:
        audit_receipt = str(args.get("audit_receipt") or "").strip()
        if not audit_receipt:
            hard_blocks.append("Loop Stage 8+ attempt requires a current passing audit receipt.")
        else:
            audit_verification = verify_receipt(
                audit_receipt,
                "audit",
                state,
                require_passed=True,
            )
            payload = audit_verification.get("payload") or {}
            if (
                not audit_verification["valid"]
                or payload.get("complete") is not True
                or payload.get("resultStatus") != "pass"
            ):
                hard_blocks.append("Loop Stage 8+ audit receipt is invalid, stale, incomplete, or not passing.")
    blind_capstone = (
        capstone_attestation is not None
        and capstone_attestation.get("valid") is True
        and capstone_attestation.get("blind") is True
        if track in {"audit", "loop"} and stage_number == 9
        else bool(args.get("blind_capstone") or False)
    )
    if stage_number == 9:
        if track == "audit":
            assert benchmark_evaluation is not None
            metrics = benchmark_evaluation["primary"]["metrics"]
            if capstone_attestation is None or capstone_attestation.get("valid") is not True:
                hard_blocks.append(
                    "Audit Stage 9 requires a current independently signed assessor attestation bound to the exact attempt and unseen challenge subject."
                )
            if not blind_capstone or metrics["p0Total"] <= 0 or metrics["p0Found"] != metrics["p0Total"]:
                hard_blocks.append("Stage 9 capstone must be blind and catch every seeded P0 finding.")
            if metrics["p1Total"] <= 0 or metrics["p1Found"] / metrics["p1Total"] < 0.8:
                hard_blocks.append("Stage 9 capstone must catch at least 80 percent of seeded P1 findings.")
            if metrics["releaseDecisionCorrect"] is not True:
                hard_blocks.append("Stage 9 capstone requires the correct release go/no-go decision.")
            if metrics["coverage"] != 1.0:
                hard_blocks.append("Audit Stage 9 capstone requires 100 percent scored fixture coverage.")
            if metrics["coverageClassificationCorrect"] is not True:
                hard_blocks.append(
                    "Audit Stage 9 capstone must report unsupported and complete coverage classifications exactly."
                )
            if metrics["severityUnderRanked"] != 0 or metrics["priorityMiscalibrated"] != 0:
                hard_blocks.append(
                    "Audit Stage 9 capstone may not under-rank seeded severity or miscalibrate seeded priority."
                )
            if metrics["precision"] < 0.8:
                hard_blocks.append("Audit Stage 9 capstone requires precision of at least 80 percent.")
            if metrics["duplicateRate"] > 0.05:
                hard_blocks.append("Audit Stage 9 capstone duplicate rate may not exceed 5 percent.")
            if metrics["falseP0"] != 0:
                hard_blocks.append("Audit Stage 9 capstone permits no false-P0 findings.")
            if benchmark_evaluation["deterministicEquivalent"] is not True:
                hard_blocks.append("Audit Stage 9 capstone requires deterministic repeated results.")
            for code in benchmark_evaluation["failureCodes"]:
                hard_blocks.append(f"Audit Stage 9 benchmark gate failed: {code}.")
        elif track == "loop":
            assert loop_capstone_evaluation is not None
            metrics = loop_capstone_evaluation
            if capstone_attestation is None or capstone_attestation.get("valid") is not True:
                hard_blocks.append(
                    "Loop Stage 9 requires a current independently signed assessor attestation bound to the exact attempt and unseen challenge subject."
                )
            if not blind_capstone or metrics["p0Total"] <= 0 or metrics["p0Found"] != metrics["p0Total"]:
                hard_blocks.append("Loop Stage 9 capstone must be blind and catch every seeded P0 finding.")
            if metrics["p1Total"] <= 0 or metrics["p1Found"] / metrics["p1Total"] < 0.8:
                hard_blocks.append("Loop Stage 9 capstone must catch at least 80 percent of seeded P1 findings.")
            if metrics["continuationDecisionCorrect"] is not True:
                hard_blocks.append("Loop Stage 9 capstone requires the correct continuation decision.")
            if metrics["releaseDecisionCorrect"] is not True:
                hard_blocks.append("Loop Stage 9 capstone requires the correct release go/no-go decision.")
            if metrics["recoveryVerified"] is not True:
                hard_blocks.append("Loop Stage 9 capstone requires independently verified recovery.")
            if metrics["evidenceComplete"] is not True:
                hard_blocks.append("Loop Stage 9 capstone requires a complete evidence dossier.")
        else:
            capstone = args.get("capstone_results") or {}
            p0_total = int(capstone.get("p0_total") or 0)
            p0_found = int(capstone.get("p0_found") or 0)
            p1_total = int(capstone.get("p1_total") or 0)
            p1_found = int(capstone.get("p1_found") or 0)
            if not blind_capstone or p0_total <= 0 or p0_found != p0_total:
                hard_blocks.append("Stage 9 capstone must be blind and catch every seeded P0 finding.")
            if p1_total <= 0 or p1_found / p1_total < 0.8:
                hard_blocks.append("Stage 9 capstone must catch at least 80 percent of seeded P1 findings.")
            if capstone.get("release_decision_correct") is not True:
                hard_blocks.append("Stage 9 capstone requires the correct release go/no-go decision.")

    eligible = (
        not hard_blocks
        and assistance in {"independent", "independent_teach"}
        and score >= (90 if stage_number == 9 else 80)
        and demonstrated_level >= 3
    )
    attempt = {
        "attemptedAt": now_iso(),
        "track": track,
        "stage": stage_number,
        "drillId": drill_id,
        "exerciseType": drill["type"],
        "assistanceLevel": assistance,
        "assessor": assessor,
        "assessorCitations": citations,
        "assessment": component_scores,
        "score": score,
        "rawLevel": raw_level,
        "demonstratedLevel": demonstrated_level,
        "artifacts": artifacts,
        "projectState": state,
        "qaEvidence": qa_verifications,
        "securityEvidence": security_verification,
        "auditEvidence": audit_verification,
        "curriculumDigest": mastery_curriculum_digest(curriculum),
        "capstoneResults": args.get("capstone_results") if stage_number == 9 and track == "engineering" else None,
        "benchmarkEvaluation": benchmark_evaluation,
        "loopCapstoneEvaluation": loop_capstone_evaluation,
        "capstoneAttestation": capstone_attestation,
        "hardGateFailures": list(dict.fromkeys(hard_blocks)),
        "blindCapstone": blind_capstone,
        "eligibleForAdvancement": eligible,
    }
    track_state["attempts"].append(attempt)
    track_state["attempts"] = track_state["attempts"][-500:]
    advancement = advancement_status(profile, stage_number, track)
    if advancement["passed"] and stage_number not in track_state["completedStages"]:
        track_state["completedStages"].append(stage_number)
        if stage_number < 9:
            track_state["currentStage"] = stage_number + 1
        else:
            track_state["masteredAt"] = now_iso()
    profile["activeTrack"] = track
    profile["updatedAt"] = now_iso()
    atomic_write_json(mastery_profile_path(), profile)
    return {
        "recorded": True,
        "attempt": attempt,
        "advanced": advancement["passed"],
        "status": tool_mastery_status({"track": track}),
        "recordType": "Local deliberate-practice record; advancement is only as trustworthy as the independent assessor evidence.",
    }


def tool_runtime_status(args: dict[str, Any]) -> dict[str, Any]:
    project_path = args.get("project_path")
    if project_path:
        binding = resolve_project_binding(str(project_path))
    else:
        binding = {
            "mode": "unbound",
            "evidenceMode": "unbound",
            "requestedPath": None,
            "projectPath": None,
            "gitRoot": None,
            "gitEvidenceAvailable": False,
            "gitEvidenceToolsAvailable": False,
            "releaseReadinessToolAvailable": False,
            "gitRequiredTools": GIT_REQUIRED_TOOLS,
            "blockedTools": [],
            "limitations": [],
            "diagnostic": "MCP mounted; no project binding was requested.",
        }
    return {
        "mcpMounted": True,
        "serverName": SERVER_NAME,
        "serverVersion": SERVER_VERSION,
        "transport": "stdio-jsonl",
        "sessionId": SERVER_SESSION_ID,
        "projectBinding": binding,
        "externalActionBoundary": {
            "defaultMode": "local-only",
            "protectedActions": list(authorization_core.ACTIONS),
            "authorizationTools": [
                "jstack_external_action_challenge",
                "jstack_external_action_authorize",
                "jstack_external_action_consume",
            ],
            "rule": "Each action requires its own signed, exact, short-lived, one-time session/Git/remote/target-bound authorization.",
        },
        "diagnostic": binding["diagnostic"],
    }


def tool_detect_project(args: dict[str, Any]) -> dict[str, Any]:
    binding = resolve_project_binding(args.get("project_path"))
    project_path = Path(binding["projectPath"])
    g_root = find_gstack_root()
    j_root = find_jstack_root()
    bin_dir = gstack_bin()
    project_config_paths = [
        project_path / ".jstack" / "project.yaml",
        project_path / ".jstack" / "project.yml",
        project_path / ".jstack" / "project.json",
        project_path / "jstack.yaml",
        project_path / "jstack.yml",
        project_path / ".gstack" / "project.yaml",
        project_path / ".gstack" / "project.yml",
        project_path / ".gstack" / "project.json",
        project_path / "gstack.yaml",
        project_path / "gstack.yml",
    ]
    project_config = [str(path) for path in project_config_paths if path.exists()]
    return {
        **binding,
        "jstackRoot": str(j_root) if j_root else None,
        "jstackInstalled": bool(j_root),
        "gstackRoot": str(g_root) if g_root else None,
        "gstackBin": str(bin_dir) if bin_dir else None,
        "gstackInstalled": bool(g_root),
        "upstreamGstackOptional": True,
        "skillCount": len(skill_files()),
        "projectConfig": project_config,
        "testCommands": discover_test_commands(project_path),
    }


def tool_list_skills(args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").lower().strip()
    limit = int(args.get("limit") or 40)
    skills = [parse_skill(path) for path in skill_files()]
    if query:
        skills = [
            skill
            for skill in skills
            if query in skill["name"].lower()
            or query in skill["directory"].lower()
            or query in skill["description"].lower()
        ]
    return {"count": len(skills), "skills": skills[: max(1, min(limit, 100))]}


def tool_read_skill(args: dict[str, Any]) -> dict[str, Any]:
    skill_name = str(args.get("skill_name") or "").strip()
    if not skill_name:
        raise ToolError("skill_name is required, for example 'qa' or 'review'.")
    for path in skill_files():
        parsed = parse_skill(path)
        names = {parsed["name"].lower(), parsed["directory"].lower()}
        if skill_name.lower() in names:
            text = path.read_text(encoding="utf-8", errors="replace")
            return {
                "skill": parsed,
                "content": truncate(text, int(args.get("max_chars") or 20_000)),
            }
    raise ToolError(f"Unknown upstream gstack skill: {skill_name}. Use jstack_list_skills first.")


def tool_plan(args: dict[str, Any]) -> dict[str, Any]:
    goal = str(args.get("goal") or "").strip()
    if not goal:
        raise ToolError("goal is required.")
    binding = resolve_project_binding(args.get("project_path"))
    quality_level = str(args.get("quality_level") or "enterprise").strip().lower()
    if quality_level not in {"standard", "enterprise"}:
        raise ToolError("quality_level must be 'standard' or 'enterprise'.")
    mastery_mode = bool(args.get("mastery_mode", True))
    learning_mode = str(args.get("learning_mode") or ("embedded" if mastery_mode else "off")).strip().lower()
    if learning_mode not in {"off", "embedded", "coach", "assessment"}:
        raise ToolError("learning_mode must be off, embedded, coach, or assessment.")
    if not mastery_mode:
        learning_mode = "off"
    team_mode = normalize_team_mode(args.get("team_mode") or "single-lead")
    capability_ids = args.get("capability_ids") or []
    classifications = classify_work(goal)
    selected = choose_skills(goal, quality_level=quality_level)
    team_plan = choose_agent_team(
        goal,
        classifications,
        quality_level=quality_level,
        team_mode=team_mode,
        capability_ids=capability_ids,
    )
    detected = tool_detect_project({"project_path": binding["requestedPath"]})
    steps = [
        {
            "gate": "Classify",
            "skill": "jstack_plan",
            "purpose": "Classify the work by risk and select the strictest matching workflow.",
            "doneWhen": "The plan names the applicable risk classes and required gates.",
        },
        {
            "gate": "Context",
            "skill": "jstack_detect_project -> context-restore",
            "purpose": "Read project instructions, restore prior context, detect repo boundaries, and load project memory where relevant.",
            "doneWhen": "Project path, repo instructions, stack, test commands, and relevant memory/docs are known.",
        },
        {
            "gate": "Planning",
            "skill": "spec -> autoplan -> plan-eng-review -> plan-ceo-review -> plan-design-review -> plan-devex-review",
            "purpose": "Convert unclear intent into acceptance criteria and review architecture/product/design/devex risk before coding.",
            "doneWhen": "The execution plan is scoped, sequenced, and matched to the risk class.",
        },
        {
            "gate": "Safety",
            "skill": "guard -> freeze -> careful",
            "purpose": "Set edit boundaries and avoid destructive or production-affecting operations without explicit approval.",
            "doneWhen": "Risky filesystem/git/production actions are either avoided or explicitly approved.",
        },
        {
            "gate": "Build",
            "skill": "normal Codex implementation tools",
            "purpose": "Make the smallest coherent change using existing architecture and proportional tests.",
            "doneWhen": "The implementation is scoped, coherent, and avoids unrelated refactors.",
        },
        {
            "gate": "Quality",
            "skill": "jstack_health -> jstack_review -> investigate -> jstack_qa",
            "purpose": "Check repo health, review diffs, run focused verification, and investigate root causes for defects.",
            "doneWhen": "Relevant lint/typecheck/test/build checks pass or failures are clearly reported.",
        },
        {
            "gate": "Security/compliance",
            "skill": "jstack_security_audit -> cso",
            "purpose": "Review auth, secrets, RBAC, PII, payment, public endpoints, webhooks, infra, and external integration boundaries.",
            "doneWhen": "Sensitive-surface risks are reviewed and release blockers are resolved or documented.",
        },
        {
            "gate": "Product/UI/QA",
            "skill": "design-review -> design-consultation -> qa -> qa-only -> browse -> benchmark",
            "purpose": "Verify user-facing behavior, visual quality, browser flows, and performance where applicable.",
            "doneWhen": "Relevant UI/product/browser/performance evidence exists for changed surfaces.",
        },
        {
            "gate": "Release",
            "skill": "jstack_ship_check -> ship -> land-and-deploy -> canary",
            "purpose": "Prepare, release, deploy, and monitor only when the user explicitly asks for release/deploy work.",
            "doneWhen": "Release work has explicit approval and ship/deploy/canary checks are complete.",
        },
        {
            "gate": "Handoff",
            "skill": "jstack_context_save -> document-release -> learn",
            "purpose": "Save decisions, files changed, checks run, risks, open items, and durable memory.",
            "doneWhen": "The handoff states what changed, what was checked, remaining risk, and next steps.",
        },
    ]
    if binding["evidenceMode"] == "artifact-only":
        artifact_replacements = {
            "Context": {
                "skill": "jstack_detect_project -> direct context inspection",
                "purpose": "Read project instructions, restore relevant durable memory, identify the authoritative source and deployment boundary, and record that Git evidence is unavailable.",
                "doneWhen": "The orchestration path, authoritative source, stack, test commands, deployment boundary, and evidence limitation are known.",
            },
            "Quality": {
                "skill": "normal Codex test/build tools + direct evidence capture",
                "purpose": "Inspect and run authorized checks directly, recording exact commands, statuses, timestamps, output, and artifact hashes without claiming JStack receipts.",
                "doneWhen": "Relevant checks pass with reviewable direct evidence, or failures and missing evidence are clearly reported.",
            },
            "Security/compliance": {
                "skill": "normal Codex security review + direct scanners",
                "purpose": "Review sensitive boundaries directly and record findings without claiming a commit-bound JStack security receipt.",
                "doneWhen": "Relevant security risks are reviewed and unresolved findings are explicit release blockers.",
            },
            "Release": {
                "skill": "artifact-only release boundary",
                "purpose": "Prepare local release artifacts and direct evidence only; v0.7 external-action authorization is unavailable without an exact Git subject, so deployment remains blocked.",
                "doneWhen": "Direct release evidence is complete and the handoff states that JStack release readiness and protected external actions remain unavailable without Git.",
            },
            "Handoff": {
                "skill": "direct handoff + durable memory",
                "purpose": "Save decisions, artifact hashes, checks, backup and rollback evidence, runtime identity, smoke results, risks, and open items outside JStack Git-bound context receipts.",
                "doneWhen": "The handoff distinguishes direct artifact evidence from unavailable Git-backed JStack certification.",
            },
        }
        for step in steps:
            replacement = artifact_replacements.get(step["gate"])
            if replacement:
                step.update(replacement)
        steps.insert(
            4,
            {
                "gate": "Artifact evidence",
                "skill": "direct hashes, tests, backup, runtime identity, rollback, monitoring, and smoke checks",
                "purpose": "Establish a reviewable evidence chain for work whose authoritative source is not bound to Git.",
                "doneWhen": "Every required artifact-only evidence item is captured, failures are explicit, and no commit-bound receipt is claimed.",
            },
        )
    release_blockers: list[str] = []
    required_gates: list[str] = []
    for classification in classifications:
        for blocker in classification.get("releaseBlockers", []):
            if blocker not in release_blockers:
                release_blockers.append(blocker)
        for gate in classification.get("requiredGates", []):
            if gate not in required_gates:
                required_gates.append(gate)
    if binding["evidenceMode"] == "artifact-only":
        release_blockers.insert(0, ARTIFACT_ONLY_RELEASE_BLOCKER)
        if "artifact-evidence" not in required_gates:
            required_gates.append("artifact-evidence")
    task_training = (
        build_task_training(goal, classifications, required_gates, learning_mode)
        if learning_mode != "off"
        else None
    )
    return {
        "goal": goal,
        "qualityLevel": quality_level,
        "masteryMode": mastery_mode,
        "learningMode": learning_mode,
        "teamMode": team_mode,
        "classifications": classifications,
        "project": detected,
        "projectBinding": binding,
        "gitRequiredTools": GIT_REQUIRED_TOOLS,
        "blockedTools": binding["blockedTools"],
        "artifactEvidenceRequirements": ARTIFACT_EVIDENCE_REQUIREMENTS if binding["evidenceMode"] == "artifact-only" else [],
        "workflowProfile": WORKFLOW_PROFILE,
        "masterySystem": mastery_system(),
        "taskTraining": task_training,
        "agentTeam": team_plan,
        "specialistCapabilityCatalog": _capability_call(
            lambda: capability_core.catalog_summary()
        ),
        "antiSlopChecklist": task_training["antiSlopChecklist"] if task_training else ANTI_SLOP_BASE,
        "recommendedSkills": selected,
        "availableWorkflowSkills": workflow_skill_names(),
        "requiredGates": required_gates,
        "releaseBlockers": release_blockers,
        "plan": steps,
        "policy": {
            "intent": "Use gstack as an enterprise workflow router and quality gate.",
            "noArbitraryShell": "Do not execute arbitrary shell commands through this MCP.",
            "approvalBoundary": "Default to local-only. Repository creation, remote add/change, commit, push, pull request, merge, tag, release, deployment, and production mutation each require their own exact signed one-time JStack external-action permit; task, phase, remediation, loop, or program approval never substitutes.",
            "productionBar": "Do not call work production-ready if required tests, security, QA, or docs for the risk class are missing.",
            "antiSlopStandard": "No fake data, fake test results, hidden assumptions, unverifiable completion claims, unrelated churn, or unapproved production mutation.",
            "masteryStandard": "For non-trivial work, include the skill stage, learning objective, expert mental model, benchmarks, review rubric, and next drill.",
            "projectBindingBoundary": "Artifact-only planning is advisory evidence capture, not commit-bound JStack QA, security, policy, context, or release certification.",
        },
    }


def tool_team_plan(args: dict[str, Any]) -> dict[str, Any]:
    goal = str(args.get("goal") or "").strip()
    if not goal:
        raise ToolError("goal is required.")
    quality_level = str(args.get("quality_level") or "enterprise").strip().lower()
    if quality_level not in {"standard", "enterprise"}:
        raise ToolError("quality_level must be 'standard' or 'enterprise'.")
    team_mode = normalize_team_mode(args.get("team_mode"))
    capability_ids = args.get("capability_ids") or []
    classifications = classify_work(goal)
    return {
        "goal": goal,
        "qualityLevel": quality_level,
        "teamMode": team_mode,
        "classifications": classifications,
        "team": choose_agent_team(
            goal,
            classifications,
            quality_level=quality_level,
            team_mode=team_mode,
            capability_ids=capability_ids,
        ),
        "capabilityCatalog": _capability_call(lambda: capability_core.catalog_summary()),
        "availableRoster": AGENT_ROSTER,
        "policy": TEAM_DISPATCH_POLICY,
        "coordinationProtocol": TEAM_COORDINATION_PROTOCOL,
    }


def tool_capability_catalog(args: dict[str, Any]) -> dict[str, Any]:
    include_details = bool(args.get("include_details", False))
    catalog = _capability_call(lambda: capability_core.load_catalog())
    summary = _capability_call(
        lambda: capability_core.catalog_summary(catalog, include_details=include_details)
    )
    role_ids = args.get("role_ids") or []
    capability_ids = args.get("capability_ids") or []
    query = str(args.get("query") or "").strip().lower()
    if role_ids:
        unknown_roles = sorted(set(str(item) for item in role_ids) - capability_core.ROSTER_ROLE_IDS)
        if unknown_roles:
            raise ToolError("Unknown role ids: " + ", ".join(unknown_roles))
    if capability_ids:
        indexed = _capability_call(lambda: capability_core.capability_by_id(catalog))
        unknown_capabilities = sorted(set(str(item) for item in capability_ids) - set(indexed))
        if unknown_capabilities:
            raise ToolError("Unknown capability ids: " + ", ".join(unknown_capabilities))
    filtered = []
    for capability in summary["capabilities"]:
        if role_ids and not set(str(item) for item in role_ids) & set(capability["allowedRoles"]):
            continue
        if capability_ids and capability["id"] not in capability_ids:
            continue
        if query and query not in " ".join(
            [
                str(capability["id"]),
                str(capability["name"]),
                str(capability["summary"]),
                " ".join(str(item) for item in capability.get("auditDomains") or []),
            ]
        ).lower():
            continue
        filtered.append(capability)
    summary["capabilities"] = filtered
    summary["resultCount"] = len(filtered)
    goal = str(args.get("goal") or "").strip()
    if goal:
        selected_roles = [str(item) for item in role_ids] or ["lead"]
        classifications = classify_work(goal)
        summary["selection"] = specialist_capability_plan(
            goal,
            classifications,
            selected_roles,
            [str(item) for item in capability_ids],
        )
    return summary


def normalize_agent_plan(agent: Any) -> dict[str, Any]:
    if not isinstance(agent, dict):
        return {}
    agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip()
    read_only = bool(agent.get("readOnly", agent.get("read_only", not bool(agent.get("mayEdit", agent.get("may_edit", False))))))
    write_scope = agent.get("writeScope", agent.get("write_scope", []))
    if isinstance(write_scope, str):
        write_scope = [write_scope]
    if not isinstance(write_scope, list):
        write_scope = []
    capability_ids = agent.get("capabilityIds", agent.get("capability_ids"))
    capabilities_provided = capability_ids is not None
    if isinstance(capability_ids, str):
        capability_ids = [capability_ids]
    if not isinstance(capability_ids, list):
        capability_ids = []
    return {
        "id": agent_id,
        "readOnly": read_only,
        "mayEdit": not read_only,
        "writeScope": [str(item).replace("\\", "/") for item in write_scope],
        "task": str(agent.get("task") or ""),
        "capabilityIds": [str(item).strip() for item in capability_ids if str(item).strip()],
        "capabilitiesProvided": capabilities_provided,
    }


def normalize_write_scope(scope: str) -> str:
    normalized = scope.strip().replace("\\", "/")
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ToolError(f"Write scope must be a non-empty repository-relative path: {scope!r}")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise ToolError(f"Write scope may not escape the repository root: {scope!r}")
    result = "/".join(parts).rstrip("/")
    if not result:
        raise ToolError(f"Write scope must identify a repository path, not the repository root: {scope!r}")
    return result


def scope_static_prefix(scope: str) -> str:
    wildcard = min([index for index in (scope.find("*"), scope.find("?"), scope.find("[")) if index >= 0] or [len(scope)])
    return scope[:wildcard].rstrip("/")


def scopes_overlap(left: str, right: str) -> bool:
    left = normalize_write_scope(left).casefold()
    right = normalize_write_scope(right).casefold()
    if left == right or fnmatch.fnmatch(left, right) or fnmatch.fnmatch(right, left):
        return True
    left_prefix = scope_static_prefix(left)
    right_prefix = scope_static_prefix(right)
    if not left_prefix or not right_prefix:
        return True
    return (
        left_prefix == right_prefix
        or left_prefix.startswith(right_prefix + "/")
        or right_prefix.startswith(left_prefix + "/")
    )


def coordination_packet_errors(
    packet: Any,
    goal: str,
    team_mode: str,
    agent_ids: list[str],
    expected_capability_plan: Optional[dict[str, Any]] = None,
) -> list[str]:
    if not isinstance(packet, dict):
        return ["Specialist dispatch requires the actual coordination_packet object, not a boolean assertion."]
    errors: list[str] = []
    required = TEAM_COORDINATION_PROTOCOL["requiredFields"]
    for field in required:
        if field == "rolesNotUsed" and team_mode == "full-team":
            continue
        value = packet.get(field)
        if value in (None, "", [], {}):
            errors.append(f"Coordination packet field '{field}' is required and must be non-empty.")
    packet_mode = normalize_team_mode(str(packet.get("mode") or team_mode))
    if packet_mode != team_mode:
        errors.append(f"Coordination packet mode '{packet_mode}' does not match dispatch mode '{team_mode}'.")
    if goal and str(packet.get("goal") or "").strip() != goal:
        errors.append("Coordination packet goal must exactly match the dispatch goal.")
    roles_used = packet.get("rolesUsed") or []
    used_ids: set[str] = set()
    if isinstance(roles_used, list):
        for role in roles_used:
            role_id = str(role.get("id") if isinstance(role, dict) else role).strip()
            if role_id:
                used_ids.add(role_id)
    if used_ids != set(agent_ids):
        errors.append("Coordination packet rolesUsed must exactly match the proposed agent ids.")
    packet_capability_plan = packet.get("capabilityPlan")
    if expected_capability_plan is not None:
        if not isinstance(packet_capability_plan, dict):
            errors.append("Coordination packet capabilityPlan must be the actual capability plan object.")
        else:
            for field in ("catalogDigest", "selectionDigest"):
                if packet_capability_plan.get(field) != expected_capability_plan.get(field):
                    errors.append(
                        f"Coordination packet capabilityPlan.{field} does not match deterministic routing."
                    )
            expected_by_role = capability_assignments_by_role(expected_capability_plan)
            for role in roles_used if isinstance(roles_used, list) else []:
                if not isinstance(role, dict):
                    continue
                role_id = str(role.get("id") or "")
                expected_ids = [
                    str(item["capabilityId"])
                    for item in expected_by_role.get(role_id, [])
                ]
                supplied_ids = role.get("capabilityIds") or []
                if supplied_ids != expected_ids:
                    errors.append(
                        f"Coordination packet role '{role_id}' capabilityIds do not match deterministic routing."
                    )
    ownership = packet.get("fileOwnershipMap")
    if not isinstance(ownership, dict):
        errors.append("Coordination packet fileOwnershipMap must be an object keyed by editing agent id.")
    return errors


def tool_dispatch_check(args: dict[str, Any]) -> dict[str, Any]:
    goal = str(args.get("goal") or "").strip()
    team_mode = normalize_team_mode(args.get("team_mode"))
    proposed = args.get("team") or args.get("agents") or {}
    if isinstance(proposed, dict):
        raw_agents = proposed.get("agents") or []
    elif isinstance(proposed, list):
        raw_agents = proposed
    else:
        raw_agents = []
    agents = [normalize_agent_plan(agent) for agent in raw_agents]
    agents = [agent for agent in agents if agent.get("id")]
    if args.get("max_specialists") is not None:
        max_specialists = int(args["max_specialists"])
    elif team_mode == "full-team":
        max_specialists = int(TEAM_DISPATCH_POLICY["fullTeamMaxSpecialists"])
    else:
        max_specialists = int(TEAM_DISPATCH_POLICY["defaultMaxSpecialists"])
    explicit_justification = str(args.get("lead_justification") or "").strip()
    explicit_release_requested = bool(args.get("explicit_release_requested") or False)
    coordination_packet = args.get("coordination_packet")
    classifications = classify_work(goal) if goal else []
    classification_ids = {item["id"] for item in classifications}
    blockers: list[str] = []
    warnings: list[str] = []

    ids = [agent["id"] for agent in agents]
    allowed_ids = {agent["id"] for agent in AGENT_ROSTER}
    unknown_ids = sorted(set(ids) - allowed_ids)
    if unknown_ids:
        blockers.append("Unknown agent ids are not allowed: " + ", ".join(unknown_ids))
    if "lead" not in ids:
        blockers.append("Agent plan must include the Lead Engineer with id 'lead'.")
    expected_capability_plan: Optional[dict[str, Any]] = None
    if not goal:
        blockers.append("A non-empty goal is required for deterministic capability validation.")
    else:
        known_role_ids = [agent_id for agent_id in ids if agent_id in allowed_ids]
        if known_role_ids:
            expected_capability_plan = specialist_capability_plan(
                goal,
                classifications,
                known_role_ids,
                [str(item) for item in (args.get("capability_ids") or [])],
            )
            expected_by_role = capability_assignments_by_role(expected_capability_plan)
            for agent in agents:
                if agent["id"] not in allowed_ids:
                    continue
                if not agent["capabilitiesProvided"]:
                    blockers.append(
                        f"Agent '{agent['id']}' must include capabilityIds from jstack_team_plan."
                    )
                    continue
                if len(agent["capabilityIds"]) != len(set(agent["capabilityIds"])):
                    blockers.append(
                        f"Agent '{agent['id']}' capabilityIds must not contain duplicates."
                    )
                try:
                    capability_core.validate_role_capabilities(
                        agent["id"], agent["capabilityIds"]
                    )
                except capability_core.CapabilityError as exc:
                    blockers.append(str(exc))
                    continue
                expected_ids = [
                    str(item["capabilityId"])
                    for item in expected_by_role.get(agent["id"], [])
                ]
                if agent["capabilityIds"] != expected_ids:
                    blockers.append(
                        f"Agent '{agent['id']}' capabilityIds do not match deterministic routing: expected "
                        + ", ".join(expected_ids)
                    )
    if team_mode == "smart-subagents":
        high_risk_requirements = {
            "production_release": {"devops", "security", "qa"},
            "security_compliance": {"security", "reviewer"},
            "ui_product": {"product", "qa"},
            "data_financial": {"quant", "reviewer"},
            "architecture": {"architect", "reviewer"},
            "product": {"product", "reviewer"},
        }
        precedence = ["production_release", "security_compliance", "ui_product", "data_financial", "architecture", "product"]
        primary = next((item for item in precedence if item in classification_ids), None)
        required_roles = set(high_risk_requirements[primary]) if primary else set()
        if primary is None and "normal" in classification_ids:
            required_roles.update({"investigator", "reviewer"})
        missing_required = sorted(required_roles - set(ids))
        if missing_required:
            blockers.append(
                "Smart-subagents plan is missing risk-required roles: " + ", ".join(missing_required)
            )
    duplicates = sorted({agent_id for agent_id in ids if ids.count(agent_id) > 1})
    if duplicates:
        blockers.append("Duplicate agent ids are not allowed: " + ", ".join(duplicates))
    specialist_count = len([agent for agent in agents if agent["id"] != "lead"])
    if specialist_count > max_specialists and not explicit_justification:
        blockers.append(f"Agent plan has {specialist_count} specialists; default maximum is {max_specialists} without lead justification.")
    if team_mode == "full-team":
        expected_ids = {agent["id"] for agent in AGENT_ROSTER}
        missing = sorted(expected_ids - set(ids))
        if missing:
            blockers.append("Full-team mode must account for all 11 roles. Missing ids: " + ", ".join(missing))
    if team_mode == "single-lead" and specialist_count:
        blockers.append("Single-lead mode may not include specialist agents.")
    if team_mode == "smart-subagents" and specialist_count > max_specialists and not explicit_justification:
        blockers.append("Smart-subagents mode should normally stay within two or three specialists unless the Lead justifies more.")
    if specialist_count > 0:
        blockers.extend(
            coordination_packet_errors(
                coordination_packet,
                goal,
                team_mode,
                ids,
                expected_capability_plan,
            )
        )
    if "production_release" in classification_ids and not explicit_release_requested:
        blockers.append(
            "Production/release-classified team planning requires an explicit request to assess that work. This flag never authorizes deploy/release actions."
        )

    write_owners: list[tuple[str, str]] = []
    ownership_map = coordination_packet.get("fileOwnershipMap", {}) if isinstance(coordination_packet, dict) else {}
    for agent in agents:
        if not agent["mayEdit"]:
            if agent["writeScope"]:
                warnings.append(f"Read-only specialist '{agent['id']}' declared a write scope that will not be honored.")
            continue
        if agent["id"] not in {"lead", "builder", "docs"}:
            blockers.append(f"Role '{agent['id']}' is read-only by policy and may not edit.")
        if agent["id"] != "lead" and not agent["writeScope"]:
            blockers.append(f"Editing specialist '{agent['id']}' requires an explicit write scope.")
        normalized_scopes: list[str] = []
        for raw_scope in agent["writeScope"]:
            try:
                scope = normalize_write_scope(raw_scope)
            except ToolError as exc:
                blockers.append(str(exc))
                continue
            if agent["id"] == "docs" and not (
                scope.startswith("docs/")
                or scope in {"README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md"}
                or scope.endswith(".md")
            ):
                blockers.append(f"Documentation specialist may not own non-documentation scope '{scope}'.")
            for existing_scope, owner in write_owners:
                if owner != agent["id"] and scopes_overlap(scope, existing_scope):
                    blockers.append(f"Write-scope overlap: '{scope}' ({agent['id']}) overlaps '{existing_scope}' ({owner}).")
            write_owners.append((scope, agent["id"]))
            normalized_scopes.append(scope)
        agent["writeScope"] = normalized_scopes
        packet_scopes = ownership_map.get(agent["id"], []) if isinstance(ownership_map, dict) else []
        if isinstance(packet_scopes, str):
            packet_scopes = [packet_scopes]
        try:
            normalized_packet_scopes = [normalize_write_scope(str(item)) for item in packet_scopes]
        except ToolError as exc:
            blockers.append(str(exc))
            normalized_packet_scopes = []
        if agent["id"] != "lead" and sorted(normalized_packet_scopes) != sorted(normalized_scopes):
            blockers.append(f"Coordination packet ownership for '{agent['id']}' must match the agent writeScope.")
    for agent in agents:
        if agent["id"] != "lead" and re.search(r"\bspawn\b|\bdelegate\b|\bsubagent\b", agent["task"], re.IGNORECASE):
            blockers.append(f"Subagent '{agent['id']}' task appears to delegate/spawn; only the Lead Engineer may orchestrate.")

    return {
        "goal": goal,
        "teamMode": team_mode,
        "valid": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "classifications": classifications,
        "specialistCount": specialist_count,
        "maxSpecialists": max_specialists,
        "leadJustification": explicit_justification,
        "coordinationPacket": coordination_packet,
        "capabilityPlan": expected_capability_plan,
        "agents": agents,
        "blockedActions": team_blocked_actions(),
        "coordinationProtocol": TEAM_COORDINATION_PROTOCOL,
        "policy": TEAM_DISPATCH_POLICY,
    }


_SPECIALIST_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_SPECIALIST_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_SPECIALIST_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")
_SPECIALIST_RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SPECIALIST_RAW_KEYS = {
    "prompt",
    "prompts",
    "rawinput",
    "rawoutput",
    "rawcontent",
    "toolarguments",
    "arguments",
    "messages",
    "modelresponse",
}


def _specialist_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _specialist_structured_limit(
    value: Any,
    field: str,
    *,
    maximum: int = SPECIALIST_MAX_STRUCTURED_BYTES,
) -> None:
    try:
        size = len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ToolError(f"{field} must be bounded JSON data.") from exc
    if size > maximum:
        raise ToolError(
            f"{field} exceeds the {maximum}-byte structured data limit."
        )


def _reject_specialist_sensitive_content(value: Any, field: str = "arguments") -> None:
    if isinstance(value, str):
        if audit_core.contains_secret_like(value):
            raise ToolError(
                f"{field} contains a secret-like value. Redact it and reference safe evidence instead."
            )
        return
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = re.sub(r"[^a-z]", "", str(key).lower())
            if normalized_key in _SPECIALIST_RAW_KEYS:
                raise ToolError(
                    f"{field}.{key} is forbidden: specialist telemetry and receipts may not store raw prompts, model output, or tool arguments."
                )
            _reject_specialist_sensitive_content(child, f"{field}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_specialist_sensitive_content(child, f"{field}[{index}]")


def _specialist_identifier(value: Any, field: str) -> str:
    normalized = str(value or "").strip()
    if not _SPECIALIST_IDENTIFIER_RE.fullmatch(normalized) or len(normalized) > 100:
        raise ToolError(f"{field} must be a lowercase kebab-case identifier.")
    return normalized


def _specialist_role_ids(values: Any, field: str = "team_role_ids") -> list[str]:
    if not isinstance(values, list) or not values:
        raise ToolError(f"{field} must be a non-empty array of JStack role ids.")
    roles = [str(item or "").strip() for item in values]
    if len(roles) != len(set(roles)):
        raise ToolError(f"{field} must not contain duplicates.")
    unknown = sorted(set(roles) - capability_core.ROSTER_ROLE_IDS)
    if unknown:
        raise ToolError(f"{field} contains unknown role ids: " + ", ".join(unknown))
    return roles


def _specialist_capability_ids(
    role_id: str, values: Any, field: str = "capability_ids"
) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ToolError(f"{field} must be a non-empty capability id array.")
    normalized = [str(item or "").strip() for item in values]
    if len(normalized) != len(set(normalized)):
        raise ToolError(f"{field} must not contain duplicates.")
    return _capability_call(
        lambda: capability_core.validate_role_capabilities(role_id, normalized)
    )


def _specialist_write_scopes(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ToolError("write_scope must be an array of repository-relative paths or globs.")
    scopes = [normalize_write_scope(str(item)) for item in values]
    if len(scopes) != len(set(scopes)):
        raise ToolError("write_scope must not contain duplicates.")
    return scopes


def _specialist_change_path(value: Any, field: str) -> str:
    path = normalize_write_scope(str(value or ""))
    if any(marker in path for marker in ("*", "?", "[")):
        raise ToolError(f"{field} must identify one concrete repository path, not a glob.")
    return path


def _path_owned_by_scope(path: str, scope: str) -> bool:
    if fnmatch.fnmatch(path, scope):
        return True
    prefix = scope_static_prefix(scope)
    return bool(prefix and (path == prefix or path.startswith(prefix + "/")))


def _specialist_timestamp(value: Any, field: str) -> _dt.datetime:
    try:
        parsed = _dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ToolError(f"{field} must be a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ToolError(f"{field} must include a timezone.")
    return parsed.astimezone(_dt.timezone.utc)


def _deterministic_specialist_team(
    goal: str,
    team_mode: str,
    explicit_capability_ids: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    classifications = classify_work(goal)
    team = choose_agent_team(
        goal,
        classifications,
        quality_level="enterprise",
        team_mode=team_mode,
        capability_ids=explicit_capability_ids,
    )
    return classifications, team


def _validate_specialist_result(
    result: Any,
    *,
    role_id: str,
    capability_ids: list[str],
    write_scopes: list[str],
    catalog: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    validate_schema_value(result, SPECIALIST_RESULT_SCHEMA, "result")
    _specialist_structured_limit(result, "result")
    _reject_specialist_sensitive_content(result, "result")
    normalized = json.loads(json.dumps(result))
    status = str(normalized["status"])
    blockers = normalized["blockers"]
    skipped = normalized["skippedChecks"]
    if status == "success" and blockers:
        raise ToolError("A successful specialist result may not contain blockers.")
    if status in {"blocked", "error"} and not blockers:
        raise ToolError(f"A {status} specialist result must contain at least one blocker.")
    if status == "partial" and not blockers and not skipped:
        raise ToolError("A partial specialist result must identify a blocker or skipped check.")

    evidence_kinds: list[str] = []
    evidence_status: dict[str, str] = {}
    evidence_references: set[str] = set()
    for index, evidence in enumerate(normalized["evidence"]):
        kind = _specialist_identifier(evidence["kind"], f"result.evidence[{index}].kind")
        if kind in evidence_kinds:
            raise ToolError(f"Duplicate specialist evidence kind: {kind}")
        evidence["kind"] = kind
        evidence_kinds.append(kind)
        evidence_status[kind] = str(evidence["status"])
        references = [str(item) for item in evidence["references"]]
        if len(references) != len(set(references)):
            raise ToolError(
                f"result.evidence[{index}].references must not contain duplicates."
            )
        evidence_references.update(references)

    indexed = _capability_call(lambda: capability_core.capability_by_id(catalog))
    required_evidence = sorted(
        {
            kind
            for capability_id in capability_ids
            for kind in indexed[capability_id]["requiredEvidence"]
        }
    )
    missing_evidence = sorted(set(required_evidence) - set(evidence_kinds))
    if missing_evidence:
        raise ToolError(
            "Specialist result is missing capability-required evidence kinds: "
            + ", ".join(missing_evidence)
        )

    finding_ids: set[str] = set()
    for index, finding in enumerate(normalized["findings"]):
        finding_id = _specialist_identifier(
            finding["findingId"], f"result.findings[{index}].findingId"
        )
        if finding_id in finding_ids:
            raise ToolError(f"Duplicate specialist findingId: {finding_id}")
        finding_ids.add(finding_id)
        finding["findingId"] = finding_id
        finding["resolutionKey"] = _specialist_identifier(
            finding["resolutionKey"], f"result.findings[{index}].resolutionKey"
        )
        finding_evidence = [
            _specialist_identifier(item, f"result.findings[{index}].evidenceKinds")
            for item in finding["evidenceKinds"]
        ]
        if len(finding_evidence) != len(set(finding_evidence)):
            raise ToolError(
                f"result.findings[{index}].evidenceKinds must not contain duplicates."
            )
        unknown_evidence = sorted(set(finding_evidence) - set(evidence_kinds))
        if unknown_evidence:
            raise ToolError(
                f"result.findings[{index}] references unknown evidence kinds: "
                + ", ".join(unknown_evidence)
            )
        finding["evidenceKinds"] = finding_evidence
        if finding.get("location"):
            finding["location"]["path"] = _specialist_change_path(
                finding["location"]["path"],
                f"result.findings[{index}].location.path",
            )
    if status == "success" and any(
        finding["disposition"] == "block" for finding in normalized["findings"]
    ):
        raise ToolError("A successful specialist result may not contain a blocking finding.")

    change_paths: set[str] = set()
    for index, change in enumerate(normalized["changes"]):
        path = _specialist_change_path(change["path"], f"result.changes[{index}].path")
        if path in change_paths:
            raise ToolError(f"Duplicate changed path in specialist result: {path}")
        change_paths.add(path)
        change["path"] = path
        if role_id not in {"lead", "builder", "docs"}:
            raise ToolError(f"Read-only role '{role_id}' may not report file changes.")
        if role_id != "lead" and not write_scopes:
            raise ToolError(f"Editing role '{role_id}' requires a non-empty write_scope.")
        if write_scopes and not any(_path_owned_by_scope(path, scope) for scope in write_scopes):
            raise ToolError(
                f"Changed path '{path}' is outside role '{role_id}' write_scope."
            )
        if role_id == "docs" and not (
            path.startswith("docs/")
            or path in {"README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md"}
            or path.endswith(".md")
        ):
            raise ToolError(f"Documentation role may not report non-document change '{path}'.")

    blocker_codes: set[str] = set()
    for index, blocker in enumerate(blockers):
        code = _specialist_identifier(blocker["code"], f"result.blockers[{index}].code")
        if code in blocker_codes:
            raise ToolError(f"Duplicate specialist blocker code: {code}")
        blocker_codes.add(code)
        blocker["code"] = code

    required_evidence_complete = all(
        evidence_status.get(kind) in {"observed", "passed"}
        for kind in required_evidence
    )
    passed = (
        status == "success"
        and not blockers
        and required_evidence_complete
        and not any(item["status"] == "failed" for item in normalized["evidence"])
    )
    return normalized, passed


def _build_specialist_telemetry(
    telemetry: Any,
    *,
    result: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    validate_schema_value(
        telemetry, SPECIALIST_TELEMETRY_INPUT_SCHEMA, "telemetry"
    )
    _specialist_structured_limit(telemetry, "telemetry")
    _reject_specialist_sensitive_content(telemetry, "telemetry")
    normalized = json.loads(json.dumps(telemetry))
    if normalized["rawContentStored"] is not False:
        raise ToolError("telemetry.rawContentStored must be false.")
    if normalized["status"] != result["status"]:
        raise ToolError("telemetry.status must exactly match result.status.")
    if not _SPECIALIST_RUN_RE.fullmatch(str(normalized["runId"])):
        raise ToolError("telemetry.runId has an invalid bounded identifier format.")
    if not _SPECIALIST_TRACE_RE.fullmatch(str(normalized["traceId"])):
        raise ToolError("telemetry.traceId must be 32 lowercase hexadecimal characters.")
    if not _SPECIALIST_SPAN_RE.fullmatch(str(normalized["spanId"])):
        raise ToolError("telemetry.spanId must be 16 lowercase hexadecimal characters.")
    started = _specialist_timestamp(normalized["startedAt"], "telemetry.startedAt")
    completed = _specialist_timestamp(normalized["completedAt"], "telemetry.completedAt")
    if completed < started:
        raise ToolError("telemetry.completedAt may not precede telemetry.startedAt.")
    elapsed_ms = int((completed - started).total_seconds() * 1000)
    if elapsed_ms > 86_400_000:
        raise ToolError("Specialist telemetry duration may not exceed 24 hours.")
    if normalized.get("durationMs") is not None and abs(int(normalized["durationMs"]) - elapsed_ms) > 1000:
        raise ToolError("telemetry.durationMs must agree with the supplied timestamps within one second.")
    normalized["durationMs"] = elapsed_ms
    evidence_references = {
        reference
        for evidence in result["evidence"]
        for reference in evidence["references"]
    }
    for index, tool_call in enumerate(normalized["toolCalls"]):
        evidence_ref = tool_call.get("evidenceRef")
        if evidence_ref and evidence_ref not in evidence_references:
            raise ToolError(
                f"telemetry.toolCalls[{index}].evidenceRef must reference result evidence."
            )
    normalized["inputDigest"] = _specialist_digest(context)
    normalized["outputDigest"] = _specialist_digest(result)
    return normalized


def tool_specialist_result(args: dict[str, Any]) -> dict[str, Any]:
    _specialist_structured_limit(args, "arguments")
    project_path = require_project_path(args.get("project_path"))
    goal = str(args.get("goal") or "").strip()
    if not goal:
        raise ToolError("goal is required.")
    team_mode = normalize_team_mode(args.get("team_mode"))
    if team_mode == "auto":
        raise ToolError("team_mode must be a resolved single-lead, smart-subagents, or full-team mode.")
    explicit_capability_ids = [str(item) for item in (args.get("explicit_capability_ids") or [])]
    _, team = _deterministic_specialist_team(
        goal, team_mode, explicit_capability_ids
    )
    expected_role_ids = [str(agent["id"]) for agent in team["agents"]]
    supplied_role_ids = _specialist_role_ids(args.get("team_role_ids"))
    if supplied_role_ids != expected_role_ids:
        raise ToolError(
            "team_role_ids must exactly match deterministic JStack routing: "
            + ", ".join(expected_role_ids)
        )
    role_id = str(args.get("role_id") or "").strip()
    if role_id not in expected_role_ids:
        raise ToolError(f"role_id '{role_id}' is not in the deterministic team plan.")
    capability_ids = _specialist_capability_ids(role_id, args.get("capability_ids"))
    expected_assignments = capability_assignments_by_role(team["capabilityPlan"])
    expected_capability_ids = [
        str(item["capabilityId"])
        for item in expected_assignments.get(role_id, [])
    ]
    if capability_ids != expected_capability_ids:
        raise ToolError(
            f"capability_ids for role '{role_id}' must exactly match deterministic routing: "
            + ", ".join(expected_capability_ids)
        )
    write_scopes = _specialist_write_scopes(args.get("write_scope"))
    catalog = _capability_call(lambda: capability_core.load_catalog())
    result, result_passed = _validate_specialist_result(
        args.get("result"),
        role_id=role_id,
        capability_ids=capability_ids,
        write_scopes=write_scopes,
        catalog=catalog,
    )
    subject_before = evidence_subject(project_path)
    goal_digest = hashlib.sha256(goal.encode("utf-8")).hexdigest()
    telemetry_context = {
        "schemaVersion": "jstack.specialist.telemetry-input.v1",
        "goalDigest": goal_digest,
        "teamMode": team_mode,
        "teamRoleIds": supplied_role_ids,
        "roleId": role_id,
        "capabilityIds": capability_ids,
        "writeScope": write_scopes,
        "catalogDigest": team["capabilityPlan"]["catalogDigest"],
        "selectionDigest": team["capabilityPlan"]["selectionDigest"],
        "gitHead": subject_before["gitHead"],
        "projectFingerprint": subject_before["projectFingerprint"],
    }
    telemetry = _build_specialist_telemetry(
        args.get("telemetry"), result=result, context=telemetry_context
    )
    telemetry_passed = telemetry["status"] == "success" and all(
        item["status"] not in {"error", "blocked"}
        for item in telemetry["toolCalls"]
    )
    passed = result_passed and telemetry_passed
    subject_after = evidence_subject(project_path)
    if any(
        subject_after[field] != subject_before[field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed while the specialist result was being validated. Re-run against one stable Git state."
        )
    result_digest = _specialist_digest(result)
    telemetry_digest = _specialist_digest(telemetry)
    payload = {
        "kind": "specialist-result",
        "schemaVersion": "jstack.specialist.receipt.v1",
        "projectPath": subject_after["gitRoot"],
        "gitHead": subject_after["gitHead"],
        "projectFingerprint": subject_after["projectFingerprint"],
        "baseRef": subject_after.get("baseRef"),
        "baseCommit": subject_after.get("baseCommit"),
        "policyDigest": subject_after["policyDigest"],
        "toolVersion": SERVER_VERSION,
        "goalDigest": goal_digest,
        "teamMode": team_mode,
        "teamRoleIds": supplied_role_ids,
        "roleId": role_id,
        "capabilityIds": capability_ids,
        "capabilityCatalogVersion": team["capabilityPlan"]["catalogVersion"],
        "capabilityCatalogDigest": team["capabilityPlan"]["catalogDigest"],
        "capabilitySelectionDigest": team["capabilityPlan"]["selectionDigest"],
        "writeScope": write_scopes,
        "result": result,
        "resultDigest": result_digest,
        "telemetry": telemetry,
        "telemetryDigest": telemetry_digest,
        "passed": passed,
    }
    receipt = issue_receipt(payload)
    return {
        "schemaVersion": "jstack.specialist.result-issuance.v1",
        "passed": passed,
        "roleId": role_id,
        "capabilityIds": capability_ids,
        "capabilityCatalogDigest": team["capabilityPlan"]["catalogDigest"],
        "capabilitySelectionDigest": team["capabilityPlan"]["selectionDigest"],
        "goalDigest": goal_digest,
        "resultDigest": result_digest,
        "telemetry": telemetry,
        "telemetryDigest": telemetry_digest,
        "specialistResultReceipt": receipt,
        "receiptDigest": _receipt_digest(receipt),
        "receiptMeaning": (
            "Session-local proof that one structured specialist result and privacy-safe telemetry envelope passed schema, capability, permission, evidence, and current-Git binding checks. It does not prove semantic truth or authorize release."
        ),
    }


def _specialist_diagnostic(
    code: str,
    message: str,
    *,
    severity: str = "error",
    role_id: Optional[str] = None,
    resolution_key: Optional[str] = None,
) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {
        "code": code,
        "severity": severity,
        "message": message,
    }
    if role_id:
        diagnostic["roleId"] = role_id
    if resolution_key:
        diagnostic["resolutionKey"] = resolution_key
    return diagnostic


def tool_specialist_handoff_check(args: dict[str, Any]) -> dict[str, Any]:
    _specialist_structured_limit(
        args,
        "arguments",
        maximum=SPECIALIST_MAX_HANDOFF_BYTES,
    )
    project_path = require_project_path(args.get("project_path"))
    goal = str(args.get("goal") or "").strip()
    if not goal:
        raise ToolError("goal is required.")
    team_mode = normalize_team_mode(args.get("team_mode"))
    if team_mode == "auto":
        raise ToolError("team_mode must be resolved before specialist handoff validation.")
    explicit_capability_ids = [str(item) for item in (args.get("explicit_capability_ids") or [])]
    _, team = _deterministic_specialist_team(
        goal, team_mode, explicit_capability_ids
    )
    expected_agents_raw = args.get("expected_agents")
    if not isinstance(expected_agents_raw, list) or not expected_agents_raw:
        raise ToolError("expected_agents must be a non-empty array from jstack_team_plan.")
    for index, expected in enumerate(expected_agents_raw):
        validate_schema_value(
            expected, SPECIALIST_EXPECTED_AGENT_SCHEMA, f"expected_agents[{index}]"
        )
    expected_role_ids = [str(item["roleId"]) for item in expected_agents_raw]
    if len(expected_role_ids) != len(set(expected_role_ids)):
        raise ToolError("expected_agents may not contain duplicate roleId values.")
    routed_role_ids = [str(agent["id"]) for agent in team["agents"]]
    if expected_role_ids != routed_role_ids:
        raise ToolError(
            "expected_agents role order must exactly match deterministic JStack routing: "
            + ", ".join(routed_role_ids)
        )
    routed_assignments = capability_assignments_by_role(team["capabilityPlan"])
    expected_by_role: dict[str, list[str]] = {}
    for index, expected in enumerate(expected_agents_raw):
        role_id = str(expected["roleId"])
        capability_ids = _specialist_capability_ids(
            role_id,
            expected["capabilityIds"],
            f"expected_agents[{index}].capabilityIds",
        )
        routed_capability_ids = [
            str(item["capabilityId"])
            for item in routed_assignments.get(role_id, [])
        ]
        if capability_ids != routed_capability_ids:
            raise ToolError(
                f"expected_agents[{index}].capabilityIds do not match deterministic routing for '{role_id}'."
            )
        expected_by_role[role_id] = capability_ids

    resolutions_raw = args.get("resolutions") or []
    if not isinstance(resolutions_raw, list):
        raise ToolError("resolutions must be an array.")
    resolutions: dict[str, dict[str, Any]] = {}
    for index, resolution in enumerate(resolutions_raw):
        validate_schema_value(
            resolution, SPECIALIST_RESOLUTION_SCHEMA, f"resolutions[{index}]"
        )
        _reject_specialist_sensitive_content(resolution, f"resolutions[{index}]")
        resolution_key = _specialist_identifier(
            resolution["resolutionKey"], f"resolutions[{index}].resolutionKey"
        )
        if resolution_key in resolutions:
            raise ToolError(f"Duplicate resolutionKey in resolutions: {resolution_key}")
        resolutions[resolution_key] = json.loads(json.dumps(resolution))

    receipts = args.get("receipts")
    if not isinstance(receipts, list) or not all(isinstance(item, str) for item in receipts):
        raise ToolError("receipts must be an array returned by jstack_specialist_result.")
    if len(receipts) > SPECIALIST_MAX_RECEIPTS or any(
        len(item) > SPECIALIST_MAX_RECEIPT_CHARS for item in receipts
    ):
        raise ToolError("receipts exceeds the bounded specialist handoff limits.")
    subject_before = evidence_subject(project_path)
    goal_digest = hashlib.sha256(goal.encode("utf-8")).hexdigest()
    diagnostics: list[dict[str, Any]] = []
    verified_by_role: dict[str, dict[str, Any]] = {}
    receipt_digests: list[str] = []
    for receipt in receipts:
        receipt_digest = _receipt_digest(receipt)
        if receipt_digest in receipt_digests:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-DUPLICATE-RECEIPT",
                    "The same specialist receipt was supplied more than once.",
                )
            )
            continue
        receipt_digests.append(receipt_digest)
        try:
            verification = verify_receipt(
                receipt,
                "specialist-result",
                subject_before,
                expected_subject=subject_before,
                require_passed=False,
            )
        except ToolError:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-RECEIPT-MALFORMED",
                    f"Receipt {receipt_digest[:12]} is malformed or from another server session.",
                )
            )
            continue
        payload = verification["payload"]
        role_id = str(payload.get("roleId") or "")
        if not verification["valid"]:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-RECEIPT-STALE",
                    f"Receipt {receipt_digest[:12]} is stale or bound to another project state.",
                    role_id=role_id or None,
                )
            )
            continue
        receipt_checks = {
            "schemaVersion": payload.get("schemaVersion") == "jstack.specialist.receipt.v1",
            "goalDigest": payload.get("goalDigest") == goal_digest,
            "teamMode": payload.get("teamMode") == team_mode,
            "teamRoleIds": payload.get("teamRoleIds") == routed_role_ids,
            "catalogDigest": payload.get("capabilityCatalogDigest")
            == team["capabilityPlan"]["catalogDigest"],
            "selectionDigest": payload.get("capabilitySelectionDigest")
            == team["capabilityPlan"]["selectionDigest"],
            "expectedRole": role_id in expected_by_role,
            "capabilityIds": payload.get("capabilityIds") == expected_by_role.get(role_id),
            "resultDigest": payload.get("resultDigest")
            == _specialist_digest(payload.get("result")),
            "telemetryDigest": payload.get("telemetryDigest")
            == _specialist_digest(payload.get("telemetry")),
        }
        if not all(receipt_checks.values()):
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-RECEIPT-MISMATCH",
                    "A specialist receipt does not match the expected goal, team, capabilities, catalog, or structured payload digests.",
                    role_id=role_id or None,
                )
            )
            continue
        if role_id in verified_by_role:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-DUPLICATE-ROLE",
                    f"Multiple receipts claim role '{role_id}'.",
                    role_id=role_id,
                )
            )
            continue
        verified_by_role[role_id] = {
            "receiptDigest": receipt_digest,
            "payload": payload,
        }
        if payload.get("passed") is not True:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-RESULT-NOT-PASSED",
                    f"Role '{role_id}' returned a structurally valid but incomplete, blocked, or failed result.",
                    role_id=role_id,
                )
            )

    for role_id in routed_role_ids:
        if role_id not in verified_by_role:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-MISSING-ROLE",
                    f"No current valid specialist receipt was supplied for role '{role_id}'.",
                    role_id=role_id,
                )
            )

    resolution_views: dict[str, list[dict[str, str]]] = {}
    resolution_evidence_references: dict[str, set[str]] = {}
    changed_path_owners: list[tuple[str, str]] = []
    telemetry_summary = {
        "runCount": 0,
        "toolCallCount": 0,
        "durationMs": 0,
        "inputTokens": 0,
        "outputTokens": 0,
        "rawContentStored": False,
    }
    for role_id, verified in verified_by_role.items():
        payload = verified["payload"]
        result = payload["result"]
        telemetry = payload["telemetry"]
        evidence_by_kind = {
            str(item["kind"]): set(str(reference) for reference in item["references"])
            for item in result.get("evidence") or []
        }
        telemetry_summary["runCount"] += 1
        telemetry_summary["toolCallCount"] += len(telemetry.get("toolCalls") or [])
        telemetry_summary["durationMs"] += int(telemetry.get("durationMs") or 0)
        telemetry_summary["inputTokens"] += int(telemetry.get("inputTokens") or 0)
        telemetry_summary["outputTokens"] += int(telemetry.get("outputTokens") or 0)
        telemetry_summary["rawContentStored"] = (
            telemetry_summary["rawContentStored"]
            or telemetry.get("rawContentStored") is not False
        )
        for finding in result.get("findings") or []:
            resolution_key = str(finding["resolutionKey"])
            resolution_views.setdefault(resolution_key, []).append(
                {
                    "roleId": role_id,
                    "disposition": str(finding["disposition"]),
                    "findingId": str(finding["findingId"]),
                }
            )
            relevant_references = resolution_evidence_references.setdefault(
                resolution_key, set()
            )
            for evidence_kind in finding.get("evidenceKinds") or []:
                relevant_references.update(evidence_by_kind.get(str(evidence_kind), set()))
        for change in result.get("changes") or []:
            path = str(change["path"])
            for prior_path, prior_owner in changed_path_owners:
                if prior_owner != role_id and scopes_overlap(path, prior_path):
                    diagnostics.append(
                        _specialist_diagnostic(
                            "JSTACK-SPECIALIST-CHANGE-OWNERSHIP-CONFLICT",
                            f"Changed path '{path}' claimed by '{role_id}' overlaps "
                            f"'{prior_path}' claimed by '{prior_owner}'.",
                            role_id=role_id,
                        )
                    )
            changed_path_owners.append((path, role_id))

    reconciliations: list[dict[str, Any]] = []
    for resolution_key, views in sorted(resolution_views.items()):
        dispositions = {
            item["disposition"]
            for item in views
            if item["disposition"] != "not-applicable"
        }
        resolution = resolutions.get(resolution_key)
        if len(dispositions) > 1 and resolution is None:
            diagnostics.append(
                _specialist_diagnostic(
                    "JSTACK-SPECIALIST-UNRESOLVED-CONTRADICTION",
                    f"Specialists disagree on '{resolution_key}': "
                    + ", ".join(
                        f"{item['roleId']}={item['disposition']}" for item in views
                    ),
                    resolution_key=resolution_key,
                )
            )
        if resolution is not None:
            unknown_references = sorted(
                set(str(item) for item in resolution["evidenceReferences"])
                - resolution_evidence_references.get(resolution_key, set())
            )
            if unknown_references:
                diagnostics.append(
                    _specialist_diagnostic(
                        "JSTACK-SPECIALIST-RESOLUTION-EVIDENCE-MISMATCH",
                        f"Lead resolution for '{resolution_key}' cites evidence not present "
                        "in the relevant signed specialist findings: "
                        + ", ".join(unknown_references),
                        resolution_key=resolution_key,
                    )
                )
            reconciliations.append(
                {
                    "resolutionKey": resolution_key,
                    "specialistViews": views,
                    "leadResolution": resolution,
                }
            )
            if resolution["decision"] == "block":
                diagnostics.append(
                    _specialist_diagnostic(
                        "JSTACK-SPECIALIST-LEAD-RESOLUTION-BLOCKS",
                        f"Lead resolution for '{resolution_key}' remains blocking.",
                        resolution_key=resolution_key,
                    )
                )
    for resolution_key in sorted(set(resolutions) - set(resolution_views)):
        diagnostics.append(
            _specialist_diagnostic(
                "JSTACK-SPECIALIST-UNREFERENCED-RESOLUTION",
                f"Resolution '{resolution_key}' does not correspond to a specialist finding.",
                severity="warning",
                resolution_key=resolution_key,
            )
        )
    subject_after = evidence_subject(project_path)
    if any(
        subject_after[field] != subject_before[field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed while specialist handoff receipts were being checked. Re-run against one stable state."
        )
    error_diagnostics = [item for item in diagnostics if item["severity"] == "error"]
    valid = not error_diagnostics
    handoff_receipt = None
    if valid:
        handoff_receipt = issue_receipt(
            {
                "kind": "specialist-handoff",
                "schemaVersion": "jstack.specialist.handoff-receipt.v1",
                "projectPath": subject_after["gitRoot"],
                "gitHead": subject_after["gitHead"],
                "projectFingerprint": subject_after["projectFingerprint"],
                "baseRef": subject_after.get("baseRef"),
                "baseCommit": subject_after.get("baseCommit"),
                "policyDigest": subject_after["policyDigest"],
                "toolVersion": SERVER_VERSION,
                "goalDigest": goal_digest,
                "teamMode": team_mode,
                "teamRoleIds": routed_role_ids,
                "capabilityCatalogDigest": team["capabilityPlan"]["catalogDigest"],
                "capabilitySelectionDigest": team["capabilityPlan"]["selectionDigest"],
                "specialistReceiptDigests": [
                    verified_by_role[role_id]["receiptDigest"]
                    for role_id in routed_role_ids
                ],
                "reconciliationDigest": _specialist_digest(reconciliations),
                "telemetrySummaryDigest": _specialist_digest(telemetry_summary),
                "passed": True,
            }
        )
    return {
        "schemaVersion": "jstack.specialist.handoff.v1",
        "valid": valid,
        "complete": valid,
        "goalDigest": goal_digest,
        "teamMode": team_mode,
        "teamRoleIds": routed_role_ids,
        "capabilityCatalogDigest": team["capabilityPlan"]["catalogDigest"],
        "capabilitySelectionDigest": team["capabilityPlan"]["selectionDigest"],
        "verifiedRoles": [
            {
                "roleId": role_id,
                "capabilityIds": expected_by_role[role_id],
                "receiptDigest": verified_by_role[role_id]["receiptDigest"],
                "resultStatus": verified_by_role[role_id]["payload"]["result"]["status"],
            }
            for role_id in routed_role_ids
            if role_id in verified_by_role
        ],
        "diagnostics": diagnostics,
        "reconciliations": reconciliations,
        "telemetrySummary": telemetry_summary,
        "specialistHandoffReceipt": handoff_receipt,
        "handoffReceiptDigest": _receipt_digest(handoff_receipt) if handoff_receipt else None,
        "receiptMeaning": (
            "When issued, this session-local receipt proves complete current-role coverage, structural validity, capability/catalog binding, Git-state binding, and explicit contradiction reconciliation. It does not prove semantic truth or authorize release."
        ),
    }


def tool_health(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    status = safe_run(["git", "status", "--short"], project_path, timeout=10)
    branch = safe_run(["git", "branch", "--show-current"], project_path, timeout=10)
    files = {
        "packageJson": (project_path / "package.json").exists(),
        "pyproject": (project_path / "pyproject.toml").exists(),
        "pytestIni": (project_path / "pytest.ini").exists(),
        "cargoToml": (project_path / "Cargo.toml").exists(),
        "goMod": (project_path / "go.mod").exists(),
        "readme": any((project_path / name).exists() for name in ["README.md", "README"]),
        "securityDoc": (project_path / "SECURITY.md").exists(),
        "architectureDoc": (project_path / "ARCHITECTURE.md").exists(),
    }
    dirty_count = len([line for line in status["stdout"].splitlines() if line.strip()])
    return {
        "projectPath": str(project_path),
        "gitRoot": git_root(project_path),
        "branch": branch["stdout"].strip() if branch["ok"] else None,
        "dirtyFileCount": dirty_count,
        "gitStatus": status,
        "projectFiles": files,
        "testCommands": discover_test_commands(project_path),
        "gstack": tool_detect_project({"project_path": str(project_path)}),
    }


def tool_review(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    evidence = git_change_evidence(project_path, str(args.get("base_ref") or "").strip() or None)
    checks = {
        "unstaged": safe_run(["git", "diff", "--check"], project_path, timeout=15),
        "staged": safe_run(["git", "diff", "--cached", "--check"], project_path, timeout=15),
    }
    if evidence["baseCommit"]:
        checks["committed"] = safe_run(
            ["git", "diff", "--check", f"{evidence['baseCommit']}..HEAD", "--"], project_path, timeout=15
        )
    failed_checks = [name for name, result in checks.items() if result["returncode"] != 0]
    combined = {
        "ok": not failed_checks,
        "returncode": 0 if not failed_checks else 1,
        "failedChecks": failed_checks,
        "checks": checks,
    }
    return {
        "projectPath": str(project_path),
        "status": safe_run(["git", "status", "--short"], project_path, timeout=10),
        "diffStat": safe_run(["git", "diff", "--stat"], project_path, timeout=15),
        "diffCheck": combined,
        "changedFiles": evidence["files"],
        "changeEvidence": evidence,
        "reviewGuidance": [
            "Lead with bugs, security risks, data leaks, auth/RBAC gaps, and missing tests.",
            "Check whether the diff touches secrets, auth boundaries, persistence, external integrations or deployment files.",
            "Run project tests outside this MCP when changes are substantial or deployment-facing.",
        ],
    }


SECRET_PATTERNS = [
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("generic_api_key_assignment", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"\n]{12,}['\"]")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
]


def should_scan(path: Path) -> bool:
    if path.suffix.lower() in {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
        ".rar", ".7z", ".sqlite", ".db", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4",
        ".mov", ".avi", ".dll", ".exe", ".dylib", ".so", ".pyc",
    }:
        return False
    return True


def tool_security_audit(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    base_ref = str(args.get("base_ref") or "").strip() or None
    subject = evidence_subject(project_path, base_ref)
    max_files = int(args.get("max_files") or 2000)
    max_file_bytes = int(args.get("max_file_bytes") or 2_000_000)
    findings: list[dict[str, Any]] = []
    scan_errors: list[dict[str, str]] = []
    skipped_binary = 0
    scanned = 0
    truncated = False
    for root, dirs, files in os.walk(project_path, followlinks=False):
        kept_dirs: list[str] = []
        for item in dirs:
            directory = Path(root) / item
            if item in EXCLUDED_DIRS:
                continue
            if directory.is_symlink():
                scan_errors.append({"path": str(directory.relative_to(project_path)), "reason": "symlink_directory_not_scanned"})
                continue
            kept_dirs.append(item)
        dirs[:] = kept_dirs
        for filename in files:
            if scanned >= max_files:
                truncated = True
                break
            path = Path(root) / filename
            relative = path.relative_to(project_path).as_posix()
            try:
                metadata = path.lstat()
            except OSError as exc:
                scan_errors.append({"path": relative, "reason": f"lstat_failed:{type(exc).__name__}"})
                continue
            if stat.S_ISLNK(metadata.st_mode):
                scan_errors.append({"path": relative, "reason": "symlink_file_not_scanned"})
                continue
            if not stat.S_ISREG(metadata.st_mode):
                scan_errors.append({"path": relative, "reason": "non_regular_file_not_scanned"})
                continue
            if not should_scan(path):
                skipped_binary += 1
                continue
            if metadata.st_size > max_file_bytes:
                scan_errors.append({"path": relative, "reason": f"file_exceeds_{max_file_bytes}_byte_limit"})
                continue
            scanned += 1
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or (
                    hasattr(metadata, "st_ino")
                    and (opened.st_ino != metadata.st_ino or opened.st_dev != metadata.st_dev)
                ):
                    os.close(descriptor)
                    scan_errors.append({"path": relative, "reason": "file_changed_during_scan"})
                    continue
                handle = os.fdopen(descriptor, "r", encoding="utf-8", errors="ignore")
            except OSError as exc:
                scan_errors.append({"path": relative, "reason": f"open_failed:{type(exc).__name__}"})
                continue
            with handle:
                for line_no, line in enumerate(handle, start=1):
                    for name, pattern in SECRET_PATTERNS:
                        if pattern.search(line):
                            findings.append({"file": relative, "line": line_no, "pattern": name})
                            break
                    if len(findings) >= 100:
                        truncated = True
                        break
            if len(findings) >= 100:
                break
        if scanned >= max_files or len(findings) >= 100:
            break
    if scanned >= max_files:
        truncated = True

    release_range_findings = 0
    if subject["baseCommit"] and subject["baseCommit"] != subject["gitHead"]:
        history = run_complete(
            [
                "git",
                "log",
                "--no-ext-diff",
                "--no-textconv",
                "--format=",
                "--patch",
                "--reverse",
                "--unified=0",
                f"{subject['baseCommit']}..{subject['gitHead']}",
                "--",
            ],
            project_path,
            timeout=30,
            max_bytes=10_000_000,
        )
        if not history["ok"]:
            scan_errors.append({"path": "<release-range>", "reason": f"history_scan_failed:{history['stderr']}"})
        else:
            for line_no, line in enumerate(_git_text(history).splitlines(), start=1):
                if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
                    continue
                for name, pattern in SECRET_PATTERNS:
                    if pattern.search(line[1:]):
                        findings.append(
                            {
                                "file": "<release-range>",
                                "line": line_no,
                                "pattern": name,
                                "scope": f"{subject['baseCommit']}..{subject['gitHead']}",
                            }
                        )
                        release_range_findings += 1
                        break
                if len(findings) >= 100:
                    truncated = True
                    break
    complete = not truncated and not scan_errors
    passed = complete and not findings
    receipt = issue_receipt(
        {
            "kind": "security",
            "projectPath": subject["gitRoot"],
            "scanRoot": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "baseRef": subject["baseRef"],
            "baseCommit": subject["baseCommit"],
            "policyDigest": subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "passed": passed,
            "findingCount": len(findings),
            "complete": complete,
        }
    )
    return {
        "projectPath": str(project_path),
        "scannedFiles": scanned,
        "skippedKnownBinaryFiles": skipped_binary,
        "truncated": truncated,
        "complete": complete,
        "scanErrors": scan_errors,
        "findingCount": len(findings),
        "releaseRangeFindingCount": release_range_findings,
        "findings": findings,
        "passed": passed,
        "evidenceReceipt": receipt,
        "evidenceState": subject,
        "note": "Bounded heuristic secret scan only. A complete clean result is required, and formal dependency/container/SAST scanning remains a separate production gate.",
    }


def audit_json_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def audit_enforce_json_limit(value: Any, label: str, maximum: int) -> None:
    try:
        size = len(
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise ToolError(f"{label} must be canonical JSON data.") from exc
    if size > maximum:
        raise ToolError(f"{label} exceeds the {maximum}-byte safety limit.")


def audit_reject_secret_values(value: Any, label: str) -> None:
    if isinstance(value, str):
        if audit_core.contains_secret_like(value):
            raise ToolError(
                f"{label} contains a secret-like value. Submit only a redacted classification and source location."
            )
        return
    if isinstance(value, dict):
        for child in value.values():
            audit_reject_secret_values(child, label)
        return
    if isinstance(value, list):
        for child in value:
            audit_reject_secret_values(child, label)


def audit_public_policy(project_path: Path) -> tuple[dict[str, Any], str]:
    policy = load_enterprise_policy(project_path)
    public = {key: value for key, value in policy.items() if not key.startswith("_")}
    return policy, audit_json_digest(public).split(":", 1)[1]


def audit_git_inventory_paths(project_path: Path) -> list[str]:
    result = run_complete(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        project_path,
        timeout=30,
        max_bytes=20_000_000,
    )
    if not result["ok"]:
        raise ToolError(f"Could not enumerate the Git audit scope: {result['stderr']}")
    paths: list[str] = []
    for raw in result["stdout"].split(b"\0"):
        if not raw:
            continue
        try:
            relative = decode_git_relative_path(raw, "audit")
            relative = audit_core.normalize_repo_path(relative, "git audit path")
        except audit_core.AuditError as exc:
            raise ToolError("Git returned an audit path that cannot be represented safely.") from exc
        candidate = project_path / relative
        if candidate.is_file() or candidate.is_symlink():
            paths.append(relative)
    return sorted(set(paths))


def audit_effective_scope(
    project_path: Path,
    evidence_mode: str,
    profile: str,
    requested_scope: Any,
    base_ref: Optional[str],
) -> tuple[str, list[str], list[str]]:
    if requested_scope is not None:
        try:
            normalized_request = audit_core.normalize_scope(requested_scope)
        except audit_core.AuditError as exc:
            raise ToolError(str(exc)) from exc
        if profile == "release":
            if normalized_request != ["."]:
                raise ToolError(
                    "Release audits require repository scope; a caller-selected partial scope cannot certify a release."
                )
            scope_mode = "repository"
        else:
            scope_mode = "explicit"
    elif evidence_mode == "git" and profile == "quick":
        normalized_request = []
        scope_mode = "changed"
    else:
        normalized_request = ["."]
        scope_mode = "repository"

    if evidence_mode != "git":
        return scope_mode, normalized_request or ["."], normalized_request or ["."]

    all_paths = audit_git_inventory_paths(project_path)
    if scope_mode == "changed":
        changed = git_change_evidence(project_path, base_ref)["files"]
        effective = [path for path in changed if path in set(all_paths)]
        if not effective:
            effective = all_paths
        return scope_mode, ["<current-delta>"], effective or ["jstack.enterprise.json"]
    if normalized_request == ["."]:
        return scope_mode, normalized_request, all_paths or ["jstack.enterprise.json"]

    expanded: list[str] = []
    for requested in normalized_request:
        exact = requested in all_paths
        prefix = requested.rstrip("/") + "/"
        matches = [path for path in all_paths if path.startswith(prefix)]
        if exact:
            expanded.append(requested)
        expanded.extend(matches)
        if not exact and not matches:
            expanded.append(requested)
    return scope_mode, normalized_request, sorted(set(expanded))


def audit_release_range_digest(project_path: Path, base_ref: Optional[str]) -> Optional[str]:
    if not base_ref:
        return None
    evidence = git_change_evidence(project_path, base_ref)
    head = run_complete(
        ["git", "rev-parse", "HEAD"],
        project_path,
        timeout=10,
        max_bytes=4096,
    )
    if not head["ok"]:
        raise ToolError("Could not bind the audit release range to HEAD.")
    return audit_json_digest(
        {
            "baseCommit": evidence.get("baseCommit"),
            "gitHead": head["stdout"].decode("ascii", errors="strict").strip(),
            "files": sorted(set(evidence.get("files") or [])),
        }
    )


def audit_inventory_summary(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": inventory.get("schemaVersion"),
        "scopeManifestDigest": inventory.get("scopeManifestDigest"),
        "fileCount": inventory.get("fileCount"),
        "totalBytes": inventory.get("totalBytes"),
        "complete": inventory.get("complete"),
        "limits": inventory.get("limits"),
        "gaps": inventory.get("gaps"),
    }


def audit_subject_for_binding(
    project_path: Path,
    evidence_mode: str,
    base_ref: Optional[str],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    if evidence_mode == "git":
        subject = evidence_subject(project_path, base_ref)
        return {
            **subject,
            "evidenceMode": "git",
            "projectPath": subject["gitRoot"],
        }
    _, policy_digest = audit_public_policy(project_path)
    return {
        "evidenceMode": "artifact-only",
        "projectPath": str(project_path),
        "gitRoot": None,
        "gitHead": None,
        "baseRef": None,
        "baseCommit": None,
        "projectFingerprint": str(inventory["scopeManifestDigest"]),
        "policyDigest": policy_digest,
        "toolVersion": SERVER_VERSION,
        "clean": None,
    }


def audit_adapter_executable(command: list[str], project_path: Path) -> dict[str, Any]:
    if command and command[0] in {"npm", "npx"}:
        return {
            "available": False,
            "reason": "project-local-node-toolchain-not-attested",
        }
    with tempfile.TemporaryDirectory(prefix="jstack-audit-plan-") as temp_home:
        env = approved_command_env([], Path(temp_home), project_path)
        executable = (
            sys.executable
            if command and command[0] in {"python", "python3", "py"}
            else shutil.which(command[0], path=env["PATH"]) if command else None
        )
    if not executable:
        return {"available": False, "reason": "executable-not-found"}
    resolved = Path(executable).resolve()
    try:
        resolved.relative_to(project_path)
    except ValueError:
        pass
    else:
        return {"available": False, "reason": "project-local-executable-rejected"}
    try:
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 100_000_000:
            return {"available": False, "reason": "executable-identity-unsupported"}
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {"available": False, "reason": "executable-unreadable"}
    return {
        "available": True,
        "resolvedExecutable": str(resolved),
        "executableSha256": digest.hexdigest(),
    }


def audit_adapter_plans(
    inventory: dict[str, Any],
    subject: dict[str, Any],
    control_digest: str,
    project_path: Path,
) -> list[dict[str, Any]]:
    binding = {
        "repositoryRoot": str(project_path),
        "revision": str(subject.get("gitHead") or inventory["scopeManifestDigest"]),
        "workspaceFingerprint": str(subject["projectFingerprint"]),
        "policyDigest": str(subject["policyDigest"]),
        "controlDigest": control_digest,
        "scopeManifestDigest": str(inventory["scopeManifestDigest"]),
    }
    discovery = audit_core.discover_adapters(inventory, binding)
    plans: list[dict[str, Any]] = []
    for raw_plan in discovery["adapters"]:
        plan = dict(raw_plan)
        executable = audit_adapter_executable(list(plan["command"]), project_path)
        adapter_version = audit_json_digest(
            {
                "adapterId": plan["adapterId"],
                "capability": plan["capability"],
                "command": plan["command"],
                "environment": plan["environment"],
            }
        )
        plan["adapterVersion"] = adapter_version
        plan["availability"] = executable
        if executable.get("available"):
            subject_value = dict(plan["approvalSubject"])
            subject_value.update(
                {
                    "adapterVersion": adapter_version,
                    "resolvedExecutable": executable["resolvedExecutable"],
                    "executableSha256": executable["executableSha256"],
                    "serverVersion": SERVER_VERSION,
                }
            )
            plan["approvalSubject"] = subject_value
            plan["approvalSubjectDigest"] = audit_json_digest(subject_value)
        plans.append(plan)
    return plans


def audit_run_approved_adapters(
    approvals: Any,
    plans: list[dict[str, Any]],
    project_path: Path,
    evidence_mode: str,
    base_ref: Optional[str],
    inventory: dict[str, Any],
    timeout: int,
) -> list[dict[str, Any]]:
    if approvals is None:
        return []
    if not isinstance(approvals, list):
        raise ToolError("adapter_approvals must be an array.")
    by_id = {plan["adapterId"]: plan for plan in plans}
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, dict):
            raise ToolError("Each adapter approval must be an object.")
        raw_subject = approval.get("subject")
        adapter_id = str(raw_subject.get("adapterId") or "") if isinstance(raw_subject, dict) else ""
        if not adapter_id or adapter_id in seen or adapter_id not in by_id:
            raise ToolError("Adapter approvals must reference unique applicable curated adapter subjects.")
        seen.add(adapter_id)
        plan = by_id[adapter_id]
        if not plan.get("availability", {}).get("available"):
            raise ToolError(f"Approved audit adapter is unavailable: {adapter_id}")
        for field in ("approvedBy", "approvalReference", "approvedAt"):
            if not isinstance(approval.get(field), str) or not str(approval[field]).strip():
                raise ToolError(f"Audit adapter approval requires non-empty {field} metadata.")
        try:
            approved_at = _dt.datetime.fromisoformat(str(approval["approvedAt"]).replace("Z", "+00:00"))
            if approved_at.tzinfo is None:
                raise ValueError("timezone required")
            approval_age = (_dt.datetime.now(_dt.timezone.utc) - approved_at.astimezone(_dt.timezone.utc)).total_seconds()
        except ValueError as exc:
            raise ToolError("Audit adapter approvedAt must be an unambiguous ISO-8601 timestamp.") from exc
        if not 0 <= approval_age <= RECEIPT_MAX_AGE_SECONDS:
            raise ToolError("Audit adapter approval is future-dated or older than the active evidence window.")
        audit_core.require_adapter_approval(approval, plan["approvalSubject"])
        current_executable = audit_adapter_executable(list(plan["command"]), project_path)
        expected_executable = plan["approvalSubject"]
        if (
            not current_executable.get("available")
            or current_executable.get("resolvedExecutable") != expected_executable["resolvedExecutable"]
            or current_executable.get("executableSha256") != expected_executable["executableSha256"]
        ):
            raise ToolError("Approved audit adapter executable identity changed before execution.")
        before = (
            project_state(project_path)["projectFingerprint"]
            if evidence_mode == "git"
            else inventory["scopeManifestDigest"]
        )
        execution = run_approved_project_command(
            list(plan["command"]),
            project_path,
            timeout=timeout,
            env_allowlist=[],
            fixed_env={**plan["environment"], "JSTACK_AUDIT_EXECUTION": "1"},
        )
        after_inventory = audit_core.inventory_repository(
            project_path,
            inventory["scope"],
            max_files=int(inventory["limits"]["maxFiles"]),
            max_bytes=int(inventory["limits"]["maxBytes"]),
            max_seconds=float(inventory["limits"]["maxSeconds"]),
        )
        after = (
            project_state(project_path)["projectFingerprint"]
            if evidence_mode == "git"
            else after_inventory["scopeManifestDigest"]
        )
        mutation_detected = before != after or after_inventory["scopeManifestDigest"] != inventory["scopeManifestDigest"]
        status = "stale" if mutation_detected else "passed" if execution["ok"] else "failed"
        if execution["returncode"] in {124, 125}:
            status = "capped"
        output_fingerprint = audit_json_digest(
            {
                "adapterVersion": plan["adapterVersion"],
                "returncode": execution["returncode"],
                "stdoutSha256": execution.get("stdoutSha256")
                or hashlib.sha256(str(execution["stdout"]).encode("utf-8")).hexdigest(),
                "stderrSha256": execution.get("stderrSha256")
                or hashlib.sha256(str(execution["stderr"]).encode("utf-8")).hexdigest(),
                "capturedOutputBytes": execution.get("capturedOutputBytes"),
                "mutationDetected": mutation_detected,
            }
        )
        result = audit_core.make_adapter_result(
            plan,
            approval,
            status,
            evidence_fingerprint=output_fingerprint,
            capped=status == "capped",
        )
        result.update(
            {
                "adapterVersion": plan["adapterVersion"],
                "returnCode": execution["returncode"],
                "mutationDetected": mutation_detected,
                "outputFingerprint": output_fingerprint,
            }
        )
        results.append(result)
    return sorted(results, key=lambda item: item["adapterId"])


def audit_artifact_secret_scan(project_path: Path, inventory: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    scanned = 0
    for item in inventory.get("files", []):
        relative = str(item.get("path") or "")
        path = project_path / relative
        if not should_scan(path):
            continue
        if int(item.get("size") or 0) > 2_000_000:
            errors.append({"path": relative, "reason": "unsupported_or_oversized"})
            continue
        try:
            content = audit_core.read_repository_file(
                project_path,
                relative,
                max_bytes=max(1, int(item.get("size") or 0)),
                max_seconds=10,
            )
        except audit_core.AuditError as exc:
            errors.append({"path": relative, "reason": f"open_failed:{type(exc).__name__}"})
            continue
        if (
            len(content) != item.get("size")
            or hashlib.sha256(content).hexdigest() != item.get("sha256")
        ):
            errors.append({"path": relative, "reason": "file_identity_changed"})
            continue
        scanned += 1
        for line_number, line in enumerate(content.decode("utf-8", errors="ignore").splitlines(), start=1):
            for pattern_name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {"file": relative, "line": line_number, "pattern": pattern_name}
                    )
                    break
            if len(findings) >= 100:
                break
        if len(findings) >= 100:
            break
    complete = inventory.get("complete") is True and not errors and len(findings) < 100
    return {
        "scannedFiles": scanned,
        "complete": complete,
        "passed": complete and not findings,
        "findingCount": len(findings),
        "findings": findings,
        "scanErrors": errors,
        "evidenceReceipt": None,
        "note": "Advisory artifact-only credential-pattern scan; no Git-bound security receipt is available.",
    }


def audit_deterministic_evidence(
    subject_digest: str,
    inventory: dict[str, Any],
    security: dict[str, Any],
    review: Optional[dict[str, Any]],
    profile: str,
    subject: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence = [
        {
            "id": "jstack-subject-binding",
            "type": "subject-binding",
            "status": "complete",
            "subjectFingerprint": subject_digest,
            "summary": "Repository or artifact subject is bound to the active MCP session.",
        },
        {
            "id": "jstack-scope-inventory",
            "type": "scope-inventory",
            "status": "complete" if inventory.get("complete") is True else "incomplete",
            "subjectFingerprint": subject_digest,
            "summary": "Bounded content-free inventory completed without a coverage gap."
            if inventory.get("complete") is True
            else "Bounded inventory reported one or more coverage gaps.",
        },
        {
            "id": "jstack-secret-scan",
            "type": "secret-scan",
            "status": "complete" if security.get("complete") is True else "incomplete",
            "subjectFingerprint": subject_digest,
            "summary": "Credential-pattern scan completed; finding values were not retained."
            if security.get("complete") is True
            else "Credential-pattern scan coverage was incomplete.",
        },
    ]
    if review is not None:
        diff_clean = bool(review.get("diffCheck", {}).get("ok"))
        evidence.append(
            {
                "id": "jstack-diff-hygiene",
                "type": "diff-hygiene",
                "status": "complete" if diff_clean else "incomplete",
                "subjectFingerprint": subject_digest,
                "summary": "Git diff whitespace/error checks passed."
                if diff_clean
                else "One or more Git diff checks failed.",
            }
        )
    if profile == "release":
        distinct = bool(subject.get("baseCommit")) and subject.get("baseCommit") != subject.get("gitHead")
        evidence.extend(
            [
                {
                    "id": "jstack-distinct-release-base",
                    "type": "distinct-release-base",
                    "status": "complete" if distinct else "incomplete",
                    "subjectFingerprint": subject_digest,
                    "summary": "Release audit has an exact distinct pre-release baseline."
                    if distinct
                    else "Release audit lacks an exact distinct pre-release baseline.",
                },
                {
                    "id": "jstack-current-security-receipt",
                    "type": "current-security-receipt",
                    "status": "complete"
                    if security.get("complete") is True and security.get("evidenceReceipt")
                    else "incomplete",
                    "subjectFingerprint": subject_digest,
                    "summary": "A current session-local security scan receipt is available."
                    if security.get("evidenceReceipt")
                    else "A Git-bound security scan receipt is unavailable.",
                },
            ]
        )
    return evidence


def audit_effective_fail_on(policy_value: Any, requested: Any) -> str:
    ordered = ["info", "low", "medium", "high", "critical", "none"]
    policy_text = str(policy_value or "high").strip().lower()
    requested_text = str(requested or policy_text).strip().lower()
    if policy_text not in ordered or requested_text not in ordered:
        raise ToolError("Audit failure threshold must be info, low, medium, high, critical, or none.")
    floor_index = min(ordered.index("high"), ordered.index(policy_text))
    return ordered[min(floor_index, ordered.index(requested_text))]


def audit_effective_required_domains(
    profile_definition: dict[str, Any], audit_policy: dict[str, Any]
) -> list[str]:
    configured = [
        "correctness" if str(item) == "reliability" else str(item)
        for item in audit_policy.get("requiredDomains", [])
    ]
    required = set(profile_definition["requiredDomains"]) | set(configured)
    return [domain for domain in audit_core.DOMAINS if domain in required]


def tool_audit(args: dict[str, Any]) -> dict[str, Any]:
    binding = resolve_project_binding(args.get("project_path"))
    project_path = Path(binding["projectPath"]).resolve()
    policy, _ = audit_public_policy(project_path)
    audit_policy = policy.get("audit", {})
    profile = str(args.get("profile") or audit_policy.get("defaultProfile") or "standard").strip().lower()
    try:
        profile_definition = audit_core.get_profile(profile)
    except audit_core.AuditError as exc:
        raise ToolError(str(exc)) from exc
    base_ref = str(args.get("base_ref") or "").strip() or None
    if binding["evidenceMode"] == "git":
        if base_ref is not None:
            resolved_base = resolve_base_ref(project_path, base_ref)
            base_ref = str(resolved_base.get("baseCommit") or "").strip() or None
        elif profile != "release":
            discovered_base = resolve_base_ref(project_path)
            base_ref = str(discovered_base.get("baseCommit") or "").strip() or None
    fail_on = audit_effective_fail_on(audit_policy.get("failOnSeverity"), args.get("fail_on"))
    required_domains = audit_effective_required_domains(profile_definition, audit_policy)
    audit_focus = str(args.get("focus") or "").strip()
    audit_capability_goal = audit_focus or (
        f"{profile} audit of " + " ".join(str(item) for item in (args.get("scope") or ["repository"]))
    )
    audit_capability_classifications = classify_work(audit_capability_goal)
    audit_capability_plan = specialist_capability_plan(
        audit_capability_goal,
        audit_capability_classifications,
        ["reviewer", "security", "qa"],
        [str(item) for item in (args.get("capability_ids") or [])],
    )
    capability_domains = set(audit_capability_plan["auditDomains"])
    required_domain_set = set(required_domains) | capability_domains
    required_domains = [
        domain for domain in audit_core.DOMAINS if domain in required_domain_set
    ]
    if profile == "quick" and args.get("adapter_approvals"):
        raise ToolError("Quick audits prohibit repository-controlled adapter execution.")
    scope_mode, requested_scope, effective_scope = audit_effective_scope(
        project_path,
        binding["evidenceMode"],
        profile,
        args.get("scope"),
        base_ref,
    )
    limits = profile_definition["limits"]
    try:
        inventory = audit_core.inventory_repository(
            project_path,
            effective_scope,
            max_files=int(limits["maxFiles"]),
            max_bytes=int(limits["maxBytes"]),
            max_seconds=float(limits["maxSeconds"]),
        )
        subject = audit_subject_for_binding(
            project_path,
            binding["evidenceMode"],
            base_ref,
            inventory,
        )
        control_digest = audit_core.controls_digest()
        subject_digest = audit_json_digest(
            {
                "projectPath": subject["projectPath"],
                "evidenceMode": subject["evidenceMode"],
                "gitHead": subject.get("gitHead"),
                "baseCommit": subject.get("baseCommit"),
                "projectFingerprint": subject["projectFingerprint"],
                "policyDigest": subject["policyDigest"],
                "controlDigest": control_digest,
                "scopeManifestDigest": inventory["scopeManifestDigest"],
                "profile": profile,
                "failOn": fail_on,
                "toolVersion": SERVER_VERSION,
            }
        )
        adapter_plans = audit_adapter_plans(inventory, subject, control_digest, project_path)
        adapter_results = audit_run_approved_adapters(
            [] if profile == "quick" else args.get("adapter_approvals"),
            adapter_plans,
            project_path,
            binding["evidenceMode"],
            base_ref,
            inventory,
            int(args.get("adapter_timeout_sec") or 120),
        )
    except audit_core.AuditError as exc:
        raise ToolError(str(exc)) from exc

    if binding["evidenceMode"] == "git":
        security = tool_security_audit(
            {
                "project_path": str(project_path),
                "base_ref": base_ref or "",
                "max_files": min(int(limits["maxFiles"]), 100_000),
                "max_file_bytes": 2_000_000,
            }
        )
        review = tool_review({"project_path": str(project_path), "base_ref": base_ref or ""})
    else:
        security = audit_artifact_secret_scan(project_path, inventory)
        review = None

    deterministic_evidence = audit_deterministic_evidence(
        subject_digest,
        inventory,
        security,
        review,
        profile,
        subject,
    )
    adapter_inventory = [
        {
            "adapterId": plan["adapterId"],
            "capability": plan["capability"],
            "adapterVersion": plan["adapterVersion"],
            "available": bool(plan.get("availability", {}).get("available")),
        }
        for plan in adapter_plans
    ]
    expires_at = (
        _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=RECEIPT_MAX_AGE_SECONDS)
    ).replace(microsecond=0).isoformat()
    token_payload = {
        "kind": "audit-session",
        "schemaVersion": "jstack.audit.session.v1",
        "expiresAt": expires_at,
        "projectPath": str(project_path),
        "evidenceMode": binding["evidenceMode"],
        "gitHead": subject.get("gitHead"),
        "baseRef": subject.get("baseRef"),
        "baseCommit": subject.get("baseCommit"),
        "projectFingerprint": subject["projectFingerprint"],
        "policyDigest": subject["policyDigest"],
        "controlDigest": control_digest,
        "subjectDigest": subject_digest,
        "scopeMode": scope_mode,
        "requestedScope": requested_scope,
        "scopeManifestDigest": inventory["scopeManifestDigest"],
        "profile": profile,
        "failOn": fail_on,
        "requiredDomains": required_domains,
        "requiredEvidence": profile_definition["requiredEvidence"],
        "adapterRequirements": profile_definition["adapterRequirements"],
        "adapterInventory": adapter_inventory,
        "adapterResults": adapter_results,
        "capabilityCatalogVersion": audit_capability_plan["catalogVersion"],
        "capabilityCatalogDigest": audit_capability_plan["catalogDigest"],
        "capabilitySelectionDigest": audit_capability_plan["selectionDigest"],
        "capabilityGoalDigest": audit_capability_plan["goalDigest"],
        "capabilityIds": [
            item["id"] for item in audit_capability_plan["selectedCapabilities"]
        ],
        "releaseRangeDigest": audit_release_range_digest(project_path, base_ref)
        if profile == "release" and binding["evidenceMode"] == "git"
        else None,
        "releaseScopeCovered": profile == "release"
        and binding["evidenceMode"] == "git"
        and scope_mode == "repository"
        and requested_scope == ["."]
        and inventory.get("complete") is True,
        "toolVersion": SERVER_VERSION,
    }
    audit_session_token = issue_receipt(token_payload)
    return {
        "schemaVersion": "jstack.audit.session-response.v1",
        "projectBinding": binding,
        "profile": profile,
        "failOn": fail_on,
        "subject": subject,
        "subjectDigest": subject_digest,
        "controlDigest": control_digest,
        "requestedScope": requested_scope,
        "scopeMode": scope_mode,
        "inventory": audit_inventory_summary(inventory),
        "coverageContract": {
            "requiredDomains": required_domains,
            "requiredEvidence": profile_definition["requiredEvidence"],
            "adapterRequirements": profile_definition["adapterRequirements"],
            "limits": profile_definition["limits"],
            "repositoryExecutionAllowed": profile != "quick",
            "capabilityRequiredDomains": audit_capability_plan["auditDomains"],
        },
        "specialistCapabilityPlan": audit_capability_plan,
        "deterministicEvidence": deterministic_evidence,
        "adapterPlans": adapter_plans,
        "adapterResults": adapter_results,
        "securityEvidence": {
            key: security.get(key)
            for key in (
                "complete",
                "passed",
                "findingCount",
                "scannedFiles",
                "scanErrors",
                "evidenceReceipt",
                "note",
            )
        },
        "reviewEvidence": {
            "diffCheck": review.get("diffCheck"),
            "changedFiles": review.get("changedFiles"),
        }
        if review
        else None,
        "auditSessionToken": audit_session_token,
        "expiresAt": expires_at,
        "limitations": binding["limitations"]
        + [
            "The deterministic MCP validates evidence structure and completeness; semantic finding truth remains a reasoned audit judgment.",
            "Curated local execution hardening is not an OS sandbox; use a container or VM for untrusted repositories.",
            "Offline adapter flags do not create an OS network firewall; use a container or VM when enforced network isolation is required.",
        ],
    }


def audit_rebuild_inventory(
    project_path: Path,
    token_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    mode = str(token_payload["evidenceMode"])
    profile = str(token_payload["profile"])
    base_ref = str(token_payload.get("baseCommit") or "").strip() or None
    scope_mode = str(token_payload["scopeMode"])
    if scope_mode == "changed":
        requested = None
    elif scope_mode == "repository":
        requested = ["."]
    else:
        requested = token_payload.get("requestedScope")
    _, _, effective_scope = audit_effective_scope(
        project_path,
        mode,
        profile,
        requested,
        base_ref,
    )
    profile_definition = audit_core.get_profile(profile)
    limits = profile_definition["limits"]
    inventory = audit_core.inventory_repository(
        project_path,
        effective_scope,
        max_files=int(limits["maxFiles"]),
        max_bytes=int(limits["maxBytes"]),
        max_seconds=float(limits["maxSeconds"]),
    )
    subject = audit_subject_for_binding(project_path, mode, base_ref, inventory)
    return inventory, subject


def audit_assert_session_subject(
    token_payload: dict[str, Any],
    binding: dict[str, Any],
    inventory: dict[str, Any],
    subject: dict[str, Any],
) -> None:
    capability_catalog = _capability_call(
        lambda: capability_core.catalog_summary()
    )
    checks = {
        "projectPath": token_payload.get("projectPath") == binding["projectPath"],
        "evidenceMode": token_payload.get("evidenceMode") == binding["evidenceMode"],
        "gitHead": token_payload.get("gitHead") == subject.get("gitHead"),
        "baseCommit": token_payload.get("baseCommit") == subject.get("baseCommit"),
        "projectFingerprint": token_payload.get("projectFingerprint") == subject.get("projectFingerprint"),
        "policyDigest": token_payload.get("policyDigest") == subject.get("policyDigest"),
        "controlDigest": token_payload.get("controlDigest") == audit_core.controls_digest(),
        "scopeManifestDigest": token_payload.get("scopeManifestDigest") == inventory.get("scopeManifestDigest"),
        "toolVersion": token_payload.get("toolVersion") == SERVER_VERSION,
        "capabilityCatalogVersion": token_payload.get("capabilityCatalogVersion")
        == capability_catalog["catalogVersion"],
        "capabilityCatalogDigest": token_payload.get("capabilityCatalogDigest")
        == capability_catalog["catalogDigest"],
    }
    if token_payload.get("profile") == "release" and binding["evidenceMode"] == "git":
        current_range_digest = audit_release_range_digest(
            Path(binding["projectPath"]),
            str(token_payload.get("baseCommit") or "").strip() or None,
        )
        checks["releaseRangeDigest"] = (
            token_payload.get("releaseRangeDigest") == current_range_digest
        )
        checks["releaseScopeCovered"] = token_payload.get("releaseScopeCovered") is True
    if not all(checks.values()):
        failed = ", ".join(key for key, value in checks.items() if not value)
        raise ToolError(f"Audit session evidence is stale; restart the audit. Changed bindings: {failed}.")


def audit_qa_evidence(
    project_path: Path,
    subject: dict[str, Any],
    subject_digest: str,
    receipts: Any,
) -> dict[str, Any]:
    if receipts is None:
        receipts = []
    if not isinstance(receipts, list) or not all(isinstance(item, str) for item in receipts):
        raise ToolError("qa_receipts must be an array of receipt strings.")
    commands = discover_test_commands(project_path)
    state = project_state(project_path)
    valid_by_key: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        verification = verify_receipt(
            receipt,
            "qa",
            state,
            expected_subject=subject,
        )
        payload = verification.get("payload") or {}
        if verification["valid"] and payload.get("commandKey"):
            valid_by_key[str(payload["commandKey"])] = payload
    missing = []
    for command in commands:
        payload = valid_by_key.get(command["key"])
        if not payload or payload.get("commandFingerprint") != command["commandFingerprint"]:
            missing.append(command["key"])
    complete = bool(commands) and not missing
    return {
        "id": "jstack-current-qa-receipts",
        "type": "current-qa-receipt",
        "status": "complete" if complete else "incomplete",
        "subjectFingerprint": subject_digest,
        "summary": "Current passing receipts cover every discovered QA command."
        if complete
        else "Current QA receipt coverage is missing or stale for: "
        + (", ".join(missing) if missing else "all commands (none discovered)"),
    }


def audit_merge_evidence(
    caller_evidence: Any,
    deterministic: list[dict[str, Any]],
    subject_digest: str,
) -> list[dict[str, Any]]:
    if not isinstance(caller_evidence, list):
        raise ToolError("evidence must be an array.")
    if len(caller_evidence) > 1000:
        raise ToolError("Audit evidence exceeds the 1000-record safety limit.")
    reserved = {item["id"] for item in deterministic}
    merged = [dict(item) for item in deterministic]
    seen = set(reserved)
    for raw in caller_evidence:
        if not isinstance(raw, dict):
            raise ToolError("Each audit evidence record must be an object.")
        item = dict(raw)
        evidence_id = str(item.get("id") or "").strip()
        if not evidence_id or evidence_id in seen:
            raise ToolError("Audit evidence identifiers must be non-empty and unique.")
        seen.add(evidence_id)
        if item.get("subjectFingerprint") != subject_digest:
            item["status"] = "stale"
            item["summary"] = "Evidence subject does not match the current audit session."
            item["subjectFingerprint"] = subject_digest
        merged.append(item)
    return merged


def audit_bind_domain_coverage(
    domain_coverage: Any,
    evidence: list[dict[str, Any]],
    subject_digest: str,
) -> Any:
    evidence_by_id = {str(item.get("id")): item for item in evidence}
    if isinstance(domain_coverage, dict):
        items = []
        for domain, value in domain_coverage.items():
            if isinstance(value, str):
                items.append({"domain": domain, "status": value})
            elif isinstance(value, dict):
                items.append({"domain": domain, **value})
            else:
                raise ToolError("domain_coverage values must be strings or objects.")
    elif isinstance(domain_coverage, list):
        items = [dict(item) if isinstance(item, dict) else item for item in domain_coverage]
    else:
        raise ToolError("domain_coverage must be an object or array.")
    if len(items) > len(audit_core.DOMAINS):
        raise ToolError("domain_coverage exceeds the supported audit domain count.")
    normalized = []
    for raw in items:
        if not isinstance(raw, dict):
            raise ToolError("Each domain coverage entry must be an object.")
        item = dict(raw)
        ids = item.get("evidenceIds", [])
        if not isinstance(ids, list) or not all(isinstance(value, str) for value in ids):
            raise ToolError("domain coverage evidenceIds must be an array of strings.")
        if item.get("status") in {"complete", "not-applicable"}:
            referenced = [evidence_by_id.get(value) for value in ids]
            exact = bool(ids) and all(
                record
                and record.get("status") == "complete"
                and record.get("subjectFingerprint") == subject_digest
                for record in referenced
            )
            if not exact:
                item["status"] = "incomplete"
                item["reason"] = "Coverage lacks complete evidence bound to this audit subject."
        normalized.append(item)
    return normalized


def audit_secret_candidates(
    security: dict[str, Any],
    subject_digest: str,
) -> list[dict[str, Any]]:
    candidates = []
    for finding in security.get("findings", []):
        path = str(finding.get("file") or "<release-range>")
        line = max(1, int(finding.get("line") or 1))
        pattern = str(finding.get("pattern") or "credential-pattern")
        candidates.append(
            {
                "schemaVersion": "jstack.audit.finding.v1",
                "ruleId": "security.secret-pattern",
                "domain": "security",
                "title": "Credential-like value detected",
                "severity": "high",
                "confidence": "high",
                "priority": "P0",
                "verificationState": "tool-confirmed",
                "status": "open",
                "location": {"path": path, "startLine": line, "endLine": line},
                "scope": [path],
                "claim": f"The bounded secret scanner detected the {pattern} pattern without retaining its value.",
                "evidence": [
                    {
                        "type": "secret-scan",
                        "status": "complete",
                        "summary": f"Pattern {pattern} detected at the reported location; raw value redacted.",
                        "subjectFingerprint": subject_digest,
                        "reproducible": True,
                    }
                ],
                "failurePath": ["Credential-like material is present in the audited tree or release range."],
                "preconditions": ["An actor, build, log, or published artifact can read the affected source history."],
                "impact": "Credential exposure may permit unauthorized access and requires immediate validation and revocation.",
                "likelihood": "Exposure depends on whether the detected value is live and who can access the repository or artifact.",
                "standards": ["NIST SSDF PW.4", "OWASP ASVS 5.0 V14"],
                "remediation": "Remove the value, revoke or rotate it, replace it with runtime secret injection, and inspect repository history.",
                "verificationPlan": "Repeat the complete current-tree and release-range secret scan after remediation and confirm revocation independently.",
                "residualRisk": "Heuristic matching can produce false positives and cannot prove whether a credential was used before revocation.",
            }
        )
    return candidates


def audit_validate_finding_locations(
    project_path: Path,
    inventory: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    files = {str(item["path"]): item for item in inventory.get("files", [])}
    for finding in findings:
        location = finding["location"]
        relative = str(location["path"])
        if relative == "<release-range>":
            continue
        manifest_item = files.get(relative)
        if not manifest_item:
            raise ToolError(f"Audit finding path is outside the bound inventory: {relative}")
        try:
            content = audit_core.read_repository_file(
                project_path,
                relative,
                max_bytes=max(1, int(manifest_item["size"])),
                max_seconds=30,
            )
        except audit_core.AuditError as exc:
            raise ToolError(f"Audit finding path could not be validated safely: {relative}") from exc
        if (
            len(content) != manifest_item["size"]
            or hashlib.sha256(content).hexdigest() != manifest_item["sha256"]
        ):
            raise ToolError(f"Audit finding source changed during range validation: {relative}")
        newline_count = content.count(b"\n")
        ends_with_newline = content.endswith(b"\n")
        line_count = max(1, newline_count if ends_with_newline else newline_count + 1)
        if int(location["endLine"]) > line_count:
            raise ToolError(
                f"Audit finding range exceeds {relative}'s {line_count} source lines."
            )


def audit_add_coverage_gap(
    coverage: dict[str, Any],
    kind: str,
    key: str,
    status: str,
    detail: str,
) -> None:
    gap = {"kind": kind, "key": key, "status": status, "detail": detail}
    if gap not in coverage["gaps"]:
        coverage["gaps"].append(gap)
        coverage["gaps"].sort(key=lambda item: (item["kind"], item["key"], item["status"], item["detail"]))
    coverage["complete"] = False


def audit_render_outputs(
    result: dict[str, Any], evidence_mode: str, requested_formats: list[str]
) -> dict[str, Any]:
    findings = result["findings"]
    gaps = result["coverage"]["gaps"]
    status = result["status"].upper()
    executive = (
        f"{status}: {result['findingCounts']['blocking']} blocking finding(s), "
        f"{len(gaps)} coverage gap(s), and {result['findingCounts']['suppressed']} accepted-risk suppression(s)."
    )
    lines = [
        "# JStack Audit Report",
        "",
        f"- Profile: `{result['profile']}`",
        f"- Status: `{result['status']}`",
        f"- Evidence mode: `{evidence_mode}`",
        f"- Failure threshold: `{result['failOn']}`",
        f"- Required coverage complete: `{str(result['coverage']['complete']).lower()}`",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("None.")
    for finding in findings:
        location = finding["location"]
        lines.extend(
            [
                "",
                f"### {finding['findingId']}: {finding['title']}",
                f"`{finding['severity']}` | `{finding['confidence']}` confidence | `{finding['priority']}` | `{finding['verificationState']}`",
                f"Location: `{location['path']}:{location['startLine']}`",
                "",
                finding["claim"],
                "",
                f"Remediation: {finding['remediation']['recommendedChange']}",
            ]
        )
    lines.extend(["", "## Coverage Gaps"])
    if not gaps:
        lines.append("None.")
    else:
        lines.extend(f"- {item['kind']} `{item['key']}`: {item['detail']}" for item in gaps)
    residual_risk = [item["detail"] for item in gaps]
    residual_risk.extend(
        finding["residualRisk"]
        for finding in findings
        if finding["verificationState"] == "unverified-hypothesis"
    )
    if evidence_mode == "artifact-only":
        residual_risk.append("Artifact-only evidence is advisory and cannot provide Git-bound release certification.")
    release_decision = (
        "go"
        if result["profile"] == "release" and evidence_mode == "git" and result["status"] == "pass"
        else "no-go"
        if result["profile"] == "release"
        else "not-applicable"
    )
    rendered: dict[str, Any] = {
        "executiveSummary": executive,
        "residualRisk": sorted(set(residual_risk)),
        "releaseDecision": release_decision,
    }
    if "markdown" in requested_formats:
        rendered["engineeringReport"] = "\n".join(lines)
        rendered["coverageMatrix"] = result["coverage"]["domains"]
    if "sarif" in requested_formats:
        rendered["sarif"] = audit_core.to_sarif(result)
    return rendered


def tool_audit_finalize(args: dict[str, Any]) -> dict[str, Any]:
    audit_reject_secret_values(
        {
            key: args.get(key)
            for key in ("domain_coverage", "evidence", "findings", "suppressions", "errors")
        },
        "Audit finalization input",
    )
    audit_enforce_json_limit(
        {
            key: args.get(key)
            for key in (
                "domain_coverage",
                "evidence",
                "findings",
                "suppressions",
                "qa_receipts",
                "errors",
            )
        },
        "Audit finalization input",
        AUDIT_MAX_STRUCTURED_INPUT_BYTES,
    )
    token = str(args.get("audit_session_token") or "").strip()
    token_payload = verify_signed_session_token(token, "audit-session")
    binding = resolve_project_binding(args.get("project_path"))
    project_path = Path(binding["projectPath"]).resolve()
    try:
        inventory, subject = audit_rebuild_inventory(project_path, token_payload)
        audit_assert_session_subject(token_payload, binding, inventory, subject)
    except audit_core.AuditError as exc:
        raise ToolError(str(exc)) from exc

    profile = str(token_payload["profile"])
    subject_digest = str(token_payload["subjectDigest"])
    evaluated_at = now_iso()
    if binding["evidenceMode"] == "git":
        security = tool_security_audit(
            {
                "project_path": str(project_path),
                "base_ref": str(token_payload.get("baseCommit") or ""),
                "max_files": min(int(inventory["limits"]["maxFiles"]), 100_000),
                "max_file_bytes": 2_000_000,
            }
        )
        review = tool_review(
            {
                "project_path": str(project_path),
                "base_ref": str(token_payload.get("baseCommit") or ""),
            }
        )
    else:
        security = audit_artifact_secret_scan(project_path, inventory)
        review = None
    deterministic = audit_deterministic_evidence(
        subject_digest,
        inventory,
        security,
        review,
        profile,
        subject,
    )
    if profile == "release" and binding["evidenceMode"] == "git":
        deterministic.append(
            audit_qa_evidence(project_path, subject, subject_digest, args.get("qa_receipts"))
        )
    evidence = audit_merge_evidence(args.get("evidence"), deterministic, subject_digest)
    domains = audit_bind_domain_coverage(args.get("domain_coverage"), evidence, subject_digest)
    try:
        coverage = audit_core.evaluate_coverage(
            profile,
            domains,
            evidence,
            token_payload.get("adapterResults", []),
            token_payload.get("requiredDomains", []),
        )
        if binding["evidenceMode"] == "artifact-only":
            audit_add_coverage_gap(
                coverage,
                "subject",
                "artifact-only",
                "unsupported",
                "Artifact-only evidence cannot produce a formal Git-bound audit pass or release decision.",
            )
        if profile == "release" and token_payload.get("releaseScopeCovered") is not True:
            audit_add_coverage_gap(
                coverage,
                "subject",
                "release-scope",
                "incomplete",
                "Release profile requires complete repository scope bound to the exact release range.",
            )
        raw_findings = args.get("findings")
        if not isinstance(raw_findings, list):
            raise ToolError("findings must be an array.")
        if len(raw_findings) > 500:
            raise ToolError("Audit findings exceed the 500-finding safety limit.")
        normalized_findings = audit_core.normalize_findings(
            [*raw_findings, *audit_secret_candidates(security, subject_digest)],
            subject_digest,
        )
        audit_validate_finding_locations(project_path, inventory, normalized_findings)
        result = audit_core.finalize_audit(
            profile,
            coverage,
            normalized_findings,
            evaluated_at,
            fail_on=str(token_payload["failOn"]),
            suppressions=args.get("suppressions") or [],
            errors=args.get("errors") or [],
        )
        final_inventory, final_subject = audit_rebuild_inventory(project_path, token_payload)
    except audit_core.AuditError as exc:
        raise ToolError(str(exc)) from exc
    stale_after_review = (
        final_inventory.get("scopeManifestDigest") != inventory.get("scopeManifestDigest")
        or final_subject.get("projectFingerprint") != subject.get("projectFingerprint")
        or final_subject.get("policyDigest") != subject.get("policyDigest")
    )
    if stale_after_review:
        audit_add_coverage_gap(
            coverage,
            "subject",
            "state-change",
            "stale",
            "Repository or policy state changed during audit finalization.",
        )
        result = audit_core.finalize_audit(
            profile,
            coverage,
            normalized_findings,
            evaluated_at,
            fail_on=str(token_payload["failOn"]),
            suppressions=args.get("suppressions") or [],
            errors=args.get("errors") or [],
        )

    requested_formats = args.get("formats") or ["json", "markdown", "sarif"]
    if (
        not isinstance(requested_formats, list)
        or not requested_formats
        or any(item not in {"json", "markdown", "sarif"} for item in requested_formats)
    ):
        raise ToolError("formats must contain json, markdown, and/or sarif.")
    outputs = audit_render_outputs(result, binding["evidenceMode"], requested_formats)
    audit_enforce_json_limit(
        outputs,
        "Audit rendered output",
        AUDIT_MAX_STRUCTURED_OUTPUT_BYTES,
    )
    receipt = None
    active_suppressions = sorted(
        [
            {
                "fingerprint": finding["fingerprint"],
                "expiresAt": finding["suppression"]["expiresAt"],
            }
            for finding in result["findings"]
            if finding.get("status") == "suppressed"
            and isinstance(finding.get("suppression"), dict)
            and finding["suppression"].get("expiresAt")
        ],
        key=lambda item: (item["expiresAt"], item["fingerprint"]),
    )
    if binding["evidenceMode"] == "git":
        expires_at = (
            _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=RECEIPT_MAX_AGE_SECONDS)
        ).replace(microsecond=0).isoformat()
        receipt = issue_receipt(
            {
                "kind": "audit",
                "schemaVersion": "jstack.audit.receipt.v1",
                "expiresAt": expires_at,
                "projectPath": subject["gitRoot"],
                "gitHead": subject["gitHead"],
                "baseRef": subject.get("baseRef"),
                "baseCommit": subject.get("baseCommit"),
                "projectFingerprint": subject["projectFingerprint"],
                "policyDigest": subject["policyDigest"],
                "controlDigest": token_payload["controlDigest"],
                "capabilityCatalogVersion": token_payload.get("capabilityCatalogVersion"),
                "capabilityCatalogDigest": token_payload.get("capabilityCatalogDigest"),
                "capabilitySelectionDigest": token_payload.get("capabilitySelectionDigest"),
                "capabilityIds": token_payload.get("capabilityIds", []),
                "toolVersion": SERVER_VERSION,
                "adapterVersions": token_payload.get("adapterInventory", []),
                "profile": profile,
                "scope": token_payload.get("requestedScope"),
                "scopeMode": token_payload.get("scopeMode"),
                "releaseScopeCovered": token_payload.get("releaseScopeCovered") is True,
                "releaseRangeDigest": token_payload.get("releaseRangeDigest"),
                "requiredDomains": token_payload.get("requiredDomains"),
                "scopeManifestDigest": inventory["scopeManifestDigest"],
                "coverageDigest": audit_json_digest(result["coverage"]),
                "findingDigest": audit_json_digest(result["findings"]),
                "resultStatus": result["status"],
                "failureThreshold": result["failOn"],
                "findingCounts": result["findingCounts"],
                "evaluatedAt": evaluated_at,
                "activeSuppressions": active_suppressions,
                "complete": result["coverage"]["complete"] is True
                and result["status"] in {"pass", "fail"},
                "passed": result["status"] == "pass",
            }
        )
    release_certification_available = (
        binding["evidenceMode"] == "git"
        and profile == "release"
        and token_payload.get("releaseScopeCovered") is True
        and result["status"] == "pass"
        and result["coverage"]["complete"] is True
    )
    response: dict[str, Any] = {
        "schemaVersion": "jstack.audit.finalization.v1",
        "executiveSummary": outputs["executiveSummary"],
        "residualRisk": outputs["residualRisk"],
        "releaseDecision": outputs["releaseDecision"],
        "requestedFormats": sorted(set(requested_formats)),
        "auditReceipt": receipt,
        "gitBoundReceiptAvailable": receipt is not None,
        "releaseCertificationAvailable": release_certification_available,
        "specialistCapabilities": {
            "catalogVersion": token_payload.get("capabilityCatalogVersion"),
            "catalogDigest": token_payload.get("capabilityCatalogDigest"),
            "selectionDigest": token_payload.get("capabilitySelectionDigest"),
            "capabilityIds": token_payload.get("capabilityIds", []),
        },
        "receiptMeaning": "Attests deterministic scope, coverage, finding/result digests, and state binding; it does not prove semantic finding truth.",
    }
    if "json" in requested_formats:
        response["result"] = result
    if "markdown" in requested_formats:
        response["engineeringReport"] = outputs["engineeringReport"]
        response["coverageMatrix"] = outputs["coverageMatrix"]
    if "sarif" in requested_formats:
        response["sarif"] = outputs["sarif"]
    audit_enforce_json_limit(
        response,
        "Audit finalization response",
        AUDIT_MAX_STRUCTURED_OUTPUT_BYTES,
    )
    return response


def tool_qa(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    commands = discover_test_commands(project_path)
    base_ref = str(args.get("base_ref") or "").strip() or None
    subject_before = evidence_subject(project_path, base_ref)
    state_before = {key: subject_before[key] for key in ("gitRoot", "gitHead", "projectFingerprint", "clean", "untrackedFiles")}
    run = bool(args.get("run") or False)
    command_key = str(args.get("command_key") or "").strip()
    result: Optional[dict[str, Any]] = None
    receipt: Optional[str] = None
    mutation_detected = False
    if run:
        if args.get("execution_approved") is not True:
            raise ToolError(
                "Running discovered commands executes repository-controlled code. Set execution_approved=true only after the user has approved trusted local execution."
            )
        trusted_revision = str(args.get("trusted_revision") or "").strip()
        trusted_fingerprint = str(args.get("trusted_project_fingerprint") or "").strip()
        trusted_policy_digest = str(args.get("trusted_policy_digest") or "").strip()
        if (
            trusted_revision != state_before["gitHead"]
            or trusted_fingerprint != state_before["projectFingerprint"]
            or trusted_policy_digest != subject_before["policyDigest"]
        ):
            raise ToolError(
                "Trusted revision/fingerprint does not match the current project state. Rediscover commands and review the project before approving execution."
            )
        if not command_key:
            raise ToolError("When run=true, command_key is required. Use jstack_qa with run=false to list allowed keys.")
        selected = next((command for command in commands if command["key"] == command_key), None)
        if not selected:
            raise ToolError(f"Unsupported command_key: {command_key}. Allowed: {[command['key'] for command in commands]}")
        env_allowlist = args.get("env_allowlist") or []
        if not isinstance(env_allowlist, list) or not all(isinstance(item, str) for item in env_allowlist):
            raise ToolError("env_allowlist must be an array of environment variable names.")
        if env_allowlist:
            raise ToolError("Forwarding host environment variables into repository-controlled QA is disabled by enterprise policy.")
        result = run_approved_project_command(
            selected["args"], project_path, timeout=int(args.get("timeout_sec") or 120), env_allowlist=env_allowlist
        )
        subject_after = evidence_subject(project_path, base_ref)
        state_after = {key: subject_after[key] for key in ("gitRoot", "gitHead", "projectFingerprint", "clean", "untrackedFiles")}
        mutation_detected = state_after["projectFingerprint"] != state_before["projectFingerprint"]
        passed = bool(result["ok"]) and not mutation_detected
        receipt = issue_receipt(
            {
                "kind": "qa",
                "projectPath": state_after["gitRoot"],
                "gitHead": state_after["gitHead"],
                "projectFingerprint": state_after["projectFingerprint"],
                "baseRef": subject_after["baseRef"],
                "baseCommit": subject_after["baseCommit"],
                "policyDigest": subject_after["policyDigest"],
                "toolVersion": SERVER_VERSION,
                "executionProfile": "local-scrubbed-no-os-sandbox-v1",
                "commandKey": selected["key"],
                "commandFingerprint": selected["commandFingerprint"],
                "returncode": result["returncode"],
                "passed": passed,
                "mutationDetected": mutation_detected,
            }
        )
    return {
        "projectPath": str(project_path),
        "evidenceState": state_before,
        "evidenceSubject": subject_before,
        "allowedCommands": commands,
        "executed": result is not None,
        "result": result,
        "mutationDetected": mutation_detected,
        "evidenceReceipt": receipt,
        "policy": (
            "Discovery is read-only. Execution runs repository-controlled code with stdin closed, a scrubbed environment, an isolated HOME, and process-group timeout handling. "
            "It still has the current user's filesystem and network privileges, so explicit trust approval and an exact revision/fingerprint are mandatory."
        ),
    }


def context_dir(project_path: Path) -> Path:
    return Path.home() / ".jstack" / "mcp-context" / project_slug(project_path)


def tool_context_save(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    summary = str(args.get("summary") or "").strip()
    if not summary:
        raise ToolError("summary is required.")
    payload = {
        "savedAt": now_iso(),
        "projectPath": str(project_path),
        "gitRoot": git_root(project_path),
        "label": str(args.get("label") or "latest"),
        "summary": summary,
        "decisions": args.get("decisions") or [],
        "nextSteps": args.get("next_steps") or [],
        "filesTouched": args.get("files_touched") or [],
    }
    target_dir = context_dir(project_path)
    timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    save_path = target_dir / f"{timestamp}.json"
    latest_path = target_dir / "latest.json"
    atomic_write_json(save_path, payload)
    atomic_write_json(latest_path, payload)
    return {"saved": True, "path": str(save_path), "latestPath": str(latest_path), "context": payload}


def tool_context_restore(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    latest_path = context_dir(project_path) / "latest.json"
    if not latest_path.exists():
        raise ToolError(f"No saved JStack MCP context for {project_path}")
    data = read_json(latest_path)
    if data is None:
        raise ToolError(f"Saved context is not valid JSON: {latest_path}")
    return {"restored": True, "path": str(latest_path), "context": data}


def tool_ship_check(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    base_ref = str(args.get("base_ref") or "").strip()
    health = tool_health({"project_path": str(project_path)})
    review = tool_review({"project_path": str(project_path), "base_ref": base_ref or None})
    docs = health["projectFiles"]
    blockers = []
    if not base_ref:
        blockers.append("Ship check requires an explicit base_ref for the release delta.")
    if review["diffCheck"]["returncode"] not in (0,):
        blockers.append("git diff --check reported whitespace or conflict-marker issues")
    if not docs.get("readme"):
        blockers.append("README is missing")
    if not health["testCommands"]:
        blockers.append("No test commands detected")
    qa_receipts = args.get("qa_receipts") or []
    if not isinstance(qa_receipts, list) or not all(isinstance(item, str) for item in qa_receipts):
        raise ToolError("qa_receipts must be an array of receipts returned by jstack_qa.")
    subject = evidence_subject(project_path, base_ref or None)
    if base_ref and subject["baseCommit"] == subject["gitHead"]:
        blockers.append("Ship check base_ref must resolve to a distinct pre-release commit, not HEAD itself.")
    valid_receipts: dict[str, dict[str, Any]] = {}
    receipt_results: list[dict[str, Any]] = []
    for receipt in qa_receipts:
        verification = verify_receipt(receipt, "qa", subject, expected_subject=subject)
        receipt_results.append(verification)
        if verification["valid"]:
            valid_receipts[str(verification["payload"].get("commandKey") or "")] = verification["payload"]
    for command in health["testCommands"]:
        payload = valid_receipts.get(command["key"])
        if not payload:
            blockers.append(f"No current passing QA receipt for '{command['key']}'.")
        elif payload.get("commandFingerprint") != command["commandFingerprint"]:
            blockers.append(f"QA receipt for '{command['key']}' does not match the current command definition.")
    return {
        "projectPath": str(project_path),
        "ready": not blockers,
        "blockers": blockers,
        "evidenceState": subject,
        "qaEvidence": receipt_results,
        "healthSummary": {
            "branch": health["branch"],
            "dirtyFileCount": health["dirtyFileCount"],
            "testCommandCount": len(health["testCommands"]),
            "docs": docs,
        },
        "recommendedGate": [
            "Run focused tests for touched code.",
            "Run security scan for auth, secrets and external integration changes.",
            "Review the complete diff before requesting any protected action.",
            "Treat this check as evidence only; consume a separate exact permit for every external action.",
            "Save context after the local handoff or separately authorized operation.",
        ],
    }


def tool_policy_check(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    goal = str(args.get("goal") or "").strip()
    explicit_release_requested = bool(args.get("explicit_release_requested") or False)
    protected_path_approval = str(args.get("protected_path_approval") or "").strip()
    target_environment = str(args.get("target_environment") or "local").strip().lower()
    policy = load_enterprise_policy(project_path)
    change_evidence = git_change_evidence(project_path, str(args.get("base_ref") or "").strip() or None)
    changed_files = change_evidence["files"]
    protected_patterns = [str(item) for item in policy.get("protectedPaths", [])]
    protected_matches = [path for path in changed_files if path_matches_patterns(path, protected_patterns)]
    classifications = classify_work(goal) if goal else []
    classification_ids = {item["id"] for item in classifications}
    blockers: list[str] = []
    warnings: list[str] = []
    required_actions: list[str] = []

    if policy.get("_usingDefault"):
        warnings.append("No project JStack policy file found; using default enterprise policy.")
        required_actions.append("Add a project policy file such as jstack.enterprise.json or jstack.yml before treating the repo as production-governed.")
    if protected_matches and not protected_path_approval:
        blockers.append("Protected paths changed without an explicit project-specific approval record.")
    elif protected_matches:
        required_actions.append(f"Verify protected-path approval reference before mutation: {protected_path_approval}")
    if target_environment in {"production", "prod"} and not explicit_release_requested:
        blockers.append("Production target selected but explicit release approval was not provided.")
    if "production_release" in classification_ids and not explicit_release_requested:
        blockers.append("Release/deploy-classified work requires explicit release approval.")
    if goal and goal_is_sensitive(goal, policy):
        required_actions.append("Run jstack_security_audit and perform a human security/compliance review before release.")
    if "data_financial" in classification_ids:
        required_actions.append("Document data source, contract assumptions, failure modes, and reconciliation/rollback path.")
    if "ui_product" in classification_ids:
        required_actions.append("Capture browser/visual QA evidence for changed user-facing flows.")
    external_policy = policy.get("externalActions") or {}
    if goal and re.search(
        r"\b(?:implement|build|finish|ship|deploy|release|publish|phase|remediat(?:e|ion))\b",
        goal,
        re.IGNORECASE,
    ):
        warnings.append(
            "Goal verbs and phase/remediation approval do not authorize repository creation, remote changes, commit, push, pull request, merge, tag, release, deployment, or production mutation."
        )

    return {
        "projectPath": str(project_path),
        "policySource": policy.get("_sourcePath"),
        "usingDefaultPolicy": bool(policy.get("_usingDefault")),
        "targetEnvironment": target_environment,
        "explicitReleaseRequested": explicit_release_requested,
        "protectedPathApproval": protected_path_approval,
        "classifications": classifications,
        "changedFiles": changed_files,
        "changeEvidence": change_evidence,
        "protectedPatterns": protected_patterns,
        "protectedMatches": protected_matches,
        "requiredChecks": policy.get("requiredChecks", []),
        "requiredActions": required_actions,
        "blockers": blockers,
        "warnings": warnings,
        "externalActionBoundary": {
            "defaultMode": external_policy.get("defaultMode", "local-only"),
            "protectedActions": external_policy.get(
                "protectedActions", list(authorization_core.ACTIONS)
            ),
            "signedAuthorizationRequired": True,
            "oneActionPerAuthorization": True,
            "authorizationRequestInGoal": False,
            "requiredProtocol": [
                "jstack_external_action_challenge",
                "external human signature",
                "jstack_external_action_authorize",
                "fresh provider observation",
                "jstack_external_action_consume",
                "one exact operation before permit expiry",
            ],
        },
        "policy": {key: value for key, value in policy.items() if not key.startswith("_")},
    }


def tool_preflight(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    goal = str(args.get("goal") or "").strip()
    strict = bool(args.get("strict", True))
    run_secret_scan = bool(args.get("run_secret_scan", True))
    policy_check = tool_policy_check(args)
    health = tool_health({"project_path": str(project_path)})
    review = tool_review({"project_path": str(project_path), "base_ref": args.get("base_ref")})
    blockers = list(policy_check["blockers"])
    warnings = list(policy_check["warnings"])

    if strict and policy_check["usingDefaultPolicy"]:
        blockers.append("Strict preflight requires a project JStack policy file.")
    if review["diffCheck"]["returncode"] != 0:
        blockers.append("git diff --check reported whitespace, conflict-marker, or patch hygiene issues.")
    if not health["testCommands"]:
        blockers.append("No test/build commands were discovered; define project checks or document why none exist.")
    if health["dirtyFileCount"] and not goal:
        warnings.append("Working tree has changes and no task goal was provided for risk classification.")

    security: Optional[dict[str, Any]] = None
    if run_secret_scan:
        security = tool_security_audit(
            {
                "project_path": str(project_path),
                "base_ref": args.get("base_ref"),
                "max_files": int(args.get("max_files") or 2000),
            }
        )
        if security["findingCount"] > 0:
            blockers.append("Secret/security scan found possible credentials or sensitive values.")
        if not security["complete"]:
            blockers.append("Secret/security scan was incomplete; truncation, symlinks, unreadable files, or size limits must be resolved.")
    elif strict and policy_check["policy"].get("security", {}).get("secretScanRequired", True):
        blockers.append("Strict preflight requires a complete secret/security scan.")

    required_evidence = [
        "Project instructions reviewed",
        "Risk class selected",
        "Changed files reviewed",
        "Protected paths checked",
        "Diff hygiene checked",
        "Test/build commands discovered",
        "Secret scan reviewed",
        "Applicable production launch profile and typed control evidence recorded",
        "Release approval recorded for production work",
        "Rollback/monitoring plan recorded for release work",
    ]
    return {
        "projectPath": str(project_path),
        "goal": goal,
        "strict": strict,
        "ready": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "requiredEvidence": required_evidence,
        "policyCheck": policy_check,
        "healthSummary": {
            "branch": health["branch"],
            "dirtyFileCount": health["dirtyFileCount"],
            "testCommands": health["testCommands"],
            "projectFiles": health["projectFiles"],
        },
        "reviewSummary": {
            "diffCheck": review["diffCheck"],
            "diffStat": review["diffStat"],
            "changedFiles": review["changedFiles"],
        },
        "securitySummary": security,
    }


def _launch_call(callback: Callable[[], Any]) -> Any:
    try:
        return callback()
    except launch_core.LaunchError as exc:
        raise ToolError(str(exc)) from exc


def _launch_safe_text(
    value: Any,
    field: str,
    *,
    minimum: int = 1,
    maximum: int = 2_000,
) -> str:
    normalized = str(value or "").strip()
    if not minimum <= len(normalized) <= maximum:
        raise ToolError(
            f"{field} must contain between {minimum} and {maximum} characters."
        )
    if audit_core.contains_secret_like(normalized):
        raise ToolError(f"{field} must not contain secret-like values.")
    return normalized


def _launch_environment(value: Any) -> str:
    environment = str(value or "production").strip().lower()
    if environment == "prod":
        environment = "production"
    if not re.fullmatch(r"[a-z][a-z0-9._-]{1,63}", environment):
        raise ToolError(
            "target_environment must be a lowercase environment identifier such as staging or production."
        )
    return environment


_LAUNCH_URL_SURFACES = frozenset(
    {
        "public-web",
        "browser-ui",
        "authenticated",
        "search-indexed",
        "performance-sensitive",
        "analytics",
        "payments",
        "commercial",
        "tracking",
        "ai-paid-endpoints",
    }
)


def _launch_target_url(
    value: Any,
    surfaces: list[str],
    target_environment: str,
) -> Optional[str]:
    raw = str(value or "").strip()
    requires_url = bool(set(surfaces) & _LAUNCH_URL_SURFACES)
    if not raw:
        if requires_url:
            raise ToolError(
                "target_url is required for the declared web, browser, analytics, payment, commercial, tracking, or costly-endpoint surfaces."
            )
        return None
    if len(raw) > 2_000:
        raise ToolError("target_url exceeds 2000 characters.")
    if audit_core.contains_secret_like(raw):
        raise ToolError("target_url must not contain secret-like values.")
    parsed = urllib.parse.urlsplit(raw)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ToolError(
            "target_url must be an HTTP(S) origin or bounded path without credentials, query text, or a fragment."
        )
    hostname = parsed.hostname.lower().rstrip(".")
    if target_environment == "production":
        local_names = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme.lower() != "https":
            raise ToolError("Production launch targets must use HTTPS.")
        if hostname in local_names or hostname.endswith((".localhost", ".local")):
            raise ToolError("Production launch targets may not use a local hostname.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ToolError("target_url contains an invalid port.") from exc
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        host += f":{port}"
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host, path, "", ""))


def _launch_artifact_path(
    project_path: Path,
    raw_path: str,
) -> tuple[Path, str, Path, str]:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = project_path / candidate
    if candidate.is_symlink():
        raise ToolError("Launch evidence artifacts may not be symlinks.")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ToolError("Launch evidence artifact is missing or inaccessible.") from exc
    allowed_roots = [
        ("project", project_path.resolve()),
        ("external-evidence", (Path.home() / ".jstack" / "evidence").resolve(strict=False)),
    ]
    selected_root: Optional[Path] = None
    selected_kind: Optional[str] = None
    relative: Optional[str] = None
    for root_kind, root in allowed_roots:
        try:
            candidate_relative = resolved.relative_to(root)
        except ValueError:
            continue
        if candidate_relative.parts:
            selected_root = root
            selected_kind = root_kind
            relative = candidate_relative.as_posix()
            break
    if selected_root is None or selected_kind is None or relative is None:
        raise ToolError(
            "Launch evidence must be inside the Git project or ~/.jstack/evidence."
        )
    metadata = resolved.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > LAUNCH_MAX_ARTIFACT_BYTES
    ):
        raise ToolError(
            "Launch evidence must be a regular file no larger than 100 MB."
        )
    return selected_root, relative, resolved, selected_kind


def _launch_file_digest(root: Path, relative_path: str) -> tuple[int, str]:
    try:
        return audit_core.digest_repository_file(
            root,
            relative_path,
            max_bytes=LAUNCH_MAX_ARTIFACT_BYTES,
            max_seconds=LAUNCH_ARTIFACT_TIMEOUT_SECONDS,
        )
    except audit_core.AuditError as exc:
        raise ToolError(
            "Launch evidence artifact could not be opened with stable file identity."
        ) from exc


def _launch_observed_at(
    value: Any,
    *,
    max_age_minutes: int,
) -> tuple[_dt.datetime, _dt.datetime]:
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    if value is None or not str(value).strip():
        observed = now
    else:
        try:
            observed = _dt.datetime.fromisoformat(
                str(value).strip().replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ToolError("observed_at must be an ISO-8601 timestamp with timezone.") from exc
        if observed.tzinfo is None:
            raise ToolError("observed_at must include a timezone.")
        observed = observed.astimezone(_dt.timezone.utc).replace(microsecond=0)
    age = (now - observed).total_seconds()
    if age < -300:
        raise ToolError("observed_at may not be more than five minutes in the future.")
    if age > max_age_minutes * 60:
        raise ToolError("The launch evidence is already older than its allowed freshness window.")
    expires = observed + _dt.timedelta(minutes=max_age_minutes)
    if expires <= now:
        raise ToolError("The launch evidence has already expired.")
    return observed, expires


def _launch_selection(
    project_path: Path,
    surfaces: list[str],
    target_environment: str,
    target_url: Optional[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    policy = load_enterprise_policy(project_path)
    launch_policy = policy.get("launch", {})
    selection = _launch_call(
        lambda: launch_core.select_controls(
            surfaces,
            target_environment=target_environment,
            target_url=target_url,
            required_control_ids=launch_policy.get("requiredControlIds", []),
            advisory_control_ids=launch_policy.get("advisoryControlIds", []),
        )
    )
    return policy, selection


def _launch_session_payload(
    project_path: Path,
    session_token: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not session_token or len(session_token) > LAUNCH_MAX_RECEIPT_CHARS:
        raise ToolError("launch_session_token is missing or exceeds the bounded receipt size.")
    state = project_state(project_path)
    first = verify_receipt(
        session_token,
        "launch-session",
        state,
        require_passed=False,
    )
    if not first["valid"]:
        raise ToolError(
            "Launch assessment token is stale or does not match the current project state."
        )
    payload = first["payload"]
    base_ref = str(payload.get("baseRef") or "").strip()
    if not base_ref:
        raise ToolError("Launch assessment token has no explicit base_ref binding.")
    subject = evidence_subject(project_path, base_ref)
    verification = verify_receipt(
        session_token,
        "launch-session",
        subject,
        expected_subject=subject,
        require_passed=False,
    )
    policy, selection = _launch_selection(
        project_path,
        list(payload.get("surfaces") or []),
        str(payload.get("targetEnvironment") or ""),
        payload.get("targetUrl"),
    )
    selected_contract = [
        {"id": control["id"], "gateLevel": control["effectiveGateLevel"]}
        for control in selection["selectedControls"]
    ]
    checks = {
        "receipt": verification["valid"],
        "schemaVersion": payload.get("schemaVersion")
        == "jstack.launch.session.v1",
        "catalogVersion": payload.get("catalogVersion")
        == selection["catalogVersion"],
        "catalogDigest": payload.get("catalogDigest")
        == selection["catalogDigest"],
        "selectionDigest": payload.get("selectionDigest")
        == selection["selectionDigest"],
        "selectedControls": payload.get("selectedControls")
        == selected_contract,
        "targetEnvironment": payload.get("targetEnvironment")
        == selection["targetEnvironment"],
        "targetUrl": payload.get("targetUrl") == selection["targetUrl"],
        "surfaces": payload.get("surfaces") == selection["surfaces"],
    }
    if not all(checks.values()):
        raise ToolError(
            "Launch assessment token no longer matches the current catalogue, policy, or applicability contract."
        )
    return payload, subject, policy, selection


def tool_launch_assess(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    base_ref = str(args.get("base_ref") or "").strip()
    if not base_ref:
        raise ToolError(
            "Launch assessment requires an explicit base_ref; automatic discovery is not a release evidence boundary."
        )
    subject = evidence_subject(project_path, base_ref)
    if subject["baseCommit"] == subject["gitHead"]:
        raise ToolError(
            "Launch base_ref must resolve to a distinct pre-release commit; HEAD cannot be its own baseline."
        )
    if not subject["clean"]:
        raise ToolError(
            "Launch assessment requires a clean committed working tree so evidence can bind an exact release candidate."
        )
    raw_surfaces = args.get("surfaces")
    if not isinstance(raw_surfaces, list):
        raise ToolError("surfaces must be an explicit array that includes 'core'.")
    surfaces = _launch_call(lambda: launch_core.normalize_surfaces(raw_surfaces))
    target_environment = _launch_environment(args.get("target_environment"))
    target_url = _launch_target_url(
        args.get("target_url"),
        surfaces,
        target_environment,
    )
    profile_owner = _launch_safe_text(
        args.get("profile_owner"),
        "profile_owner",
        maximum=200,
    )
    raw_reference = args.get("profile_reference")
    if target_environment == "production":
        profile_reference = _launch_safe_text(
            raw_reference,
            "profile_reference",
            maximum=500,
        )
    else:
        profile_reference = (
            _launch_safe_text(
                raw_reference,
                "profile_reference",
                maximum=500,
            )
            if str(raw_reference or "").strip()
            else "not-required-for-non-production"
        )
    policy, selection = _launch_selection(
        project_path,
        surfaces,
        target_environment,
        target_url,
    )
    if policy.get("launch", {}).get("requireProfileDeclaration") and not profile_owner:
        raise ToolError("Launch policy requires an accountable profile owner.")
    expires = (
        _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
        + _dt.timedelta(seconds=LAUNCH_SESSION_MAX_AGE_SECONDS)
    ).isoformat()
    selected_contract = [
        {"id": control["id"], "gateLevel": control["effectiveGateLevel"]}
        for control in selection["selectedControls"]
    ]
    token = issue_receipt(
        {
            "kind": "launch-session",
            "schemaVersion": "jstack.launch.session.v1",
            "projectPath": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "baseRef": subject["baseRef"],
            "baseCommit": subject["baseCommit"],
            "policyDigest": subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "catalogVersion": selection["catalogVersion"],
            "catalogDigest": selection["catalogDigest"],
            "selectionDigest": selection["selectionDigest"],
            "surfaces": selection["surfaces"],
            "targetEnvironment": target_environment,
            "targetUrl": target_url,
            "selectedControls": selected_contract,
            "profileOwner": profile_owner,
            "profileReferenceDigest": hashlib.sha256(
                profile_reference.encode("utf-8")
            ).hexdigest(),
            "expiresAt": expires,
            "passed": False,
        }
    )
    return {
        "schemaVersion": "jstack.launch.assessment.v1",
        "projectPath": str(project_path),
        "baseRef": subject["baseRef"],
        "targetEnvironment": target_environment,
        "targetUrl": target_url,
        "profile": {
            "owner": profile_owner,
            "referenceDigest": hashlib.sha256(
                profile_reference.encode("utf-8")
            ).hexdigest(),
            "surfaces": selection["surfaces"],
            "declarationIsInference": False,
        },
        "catalog": {
            "schemaVersion": launch_core.CATALOG_SCHEMA_VERSION,
            "version": selection["catalogVersion"],
            "digest": selection["catalogDigest"],
            "sourceProvenance": launch_core.load_catalog()["sourceProvenance"],
        },
        "selection": selection,
        "launchSessionToken": token,
        "expiresAt": expires,
        "readyToCollect": True,
        "executionAuthorized": False,
        "evidenceContract": {
            "statuses": list(launch_core.FINAL_STATUSES),
            "evidenceKinds": list(launch_core.EVIDENCE_KINDS),
            "artifactRoots": [str(project_path), "~/.jstack/evidence"],
            "artifactMaximumBytes": LAUNCH_MAX_ARTIFACT_BYTES,
            "rawArtifactContentReturned": False,
            "semanticTruthCertified": False,
        },
        "externalActionBoundary": {
            "assessmentIsNotAuthority": True,
            "protectedActions": list(authorization_core.ACTIONS),
        },
    }


def tool_launch_evidence_register(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    session_token = str(args.get("launch_session_token") or "").strip()
    session, subject, policy, selection = _launch_session_payload(
        project_path,
        session_token,
    )
    control_id = str(args.get("control_id") or "").strip()
    selected = {
        str(control["id"]): control for control in selection["selectedControls"]
    }
    if control_id not in selected:
        raise ToolError(
            "control_id is not selected by the current launch applicability contract."
        )
    control = selected[control_id]
    evidence_kind = str(args.get("evidence_kind") or "").strip()
    if evidence_kind not in control["evidenceKinds"]:
        raise ToolError(
            "evidence_kind is not permitted for this launch control; use one of: "
            + ", ".join(control["evidenceKinds"])
        )
    outcome = str(args.get("outcome") or "").strip().lower()
    if outcome not in {"pass", "fail", "incomplete", "not-applicable"}:
        raise ToolError(
            "outcome must be pass, fail, incomplete, or not-applicable."
        )
    if outcome == "not-applicable" and not control["allowNotApplicable"]:
        raise ToolError(
            "This selected launch control does not permit a not-applicable outcome. Correct the surface declaration or provide pass/fail evidence."
        )
    verifier = _launch_safe_text(args.get("verifier"), "verifier", maximum=200)
    source_reference = _launch_safe_text(
        args.get("source_reference"),
        "source_reference",
        maximum=500,
    )
    summary = _launch_safe_text(
        args.get("summary"),
        "summary",
        minimum=10,
        maximum=2_000,
    )
    artifact_root, artifact_relative, artifact, artifact_root_kind = (
        _launch_artifact_path(
            project_path,
            str(args.get("artifact_path") or ""),
        )
    )
    artifact_size, artifact_digest = _launch_file_digest(
        artifact_root,
        artifact_relative,
    )
    max_age_minutes = min(
        int(control["maxAgeMinutes"]),
        int(policy.get("launch", {}).get("maxEvidenceAgeMinutes", 1440)),
    )
    observed, expires = _launch_observed_at(
        args.get("observed_at"),
        max_age_minutes=max_age_minutes,
    )
    session_digest = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    receipt = issue_receipt(
        {
            "kind": "launch-evidence",
            "schemaVersion": "jstack.launch.evidence.v1",
            "projectPath": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "baseCommit": subject["baseCommit"],
            "policyDigest": subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "catalogVersion": selection["catalogVersion"],
            "catalogDigest": selection["catalogDigest"],
            "selectionDigest": selection["selectionDigest"],
            "launchSessionDigest": session_digest,
            "controlId": control_id,
            "category": control["category"],
            "gateLevel": control["effectiveGateLevel"],
            "evidenceKind": evidence_kind,
            "outcome": outcome,
            "verifier": verifier,
            "sourceReferenceDigest": hashlib.sha256(
                source_reference.encode("utf-8")
            ).hexdigest(),
            "summaryDigest": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
            "artifactSha256": artifact_digest,
            "artifactSize": artifact_size,
            "artifactPathDigest": hashlib.sha256(
                str(artifact).encode("utf-8")
            ).hexdigest(),
            "artifactRootKind": artifact_root_kind,
            "observedAt": observed.isoformat(),
            "expiresAt": expires.isoformat(),
            "passed": outcome == "pass",
        }
    )
    return {
        "schemaVersion": "jstack.launch.evidence-registration.v1",
        "control": {
            "id": control_id,
            "category": control["category"],
            "gateLevel": control["effectiveGateLevel"],
            "evidenceKind": evidence_kind,
            "outcome": outcome,
        },
        "artifact": {
            "sha256": artifact_digest,
            "size": artifact_size,
            "pathDigest": hashlib.sha256(str(artifact).encode("utf-8")).hexdigest(),
            "rootKind": artifact_root_kind,
            "contentReturned": False,
        },
        "observedAt": observed.isoformat(),
        "expiresAt": expires.isoformat(),
        "launchEvidenceReceipt": receipt,
        "executionAuthorized": False,
        "attestationLimit": "JStack verified bounded artifact identity, freshness, and contract binding. The named verifier remains accountable for the semantic outcome.",
    }


def _launch_waivers(
    values: Any,
    *,
    selected: dict[str, dict[str, Any]],
    policy: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    if values is None:
        return {}
    if not isinstance(values, list) or len(values) > LAUNCH_MAX_RECEIPTS:
        raise ToolError("waivers must be an array of at most 100 records.")
    if values and not policy.get("launch", {}).get("allowWaivers", True):
        raise ToolError("Enterprise launch policy disables waivers.")
    expected_fields = {
        "control_id",
        "owner",
        "reason",
        "approval_reference",
        "expires_at",
        "compensating_control",
        "residual_risk",
    }
    now = _dt.datetime.now(_dt.timezone.utc)
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(values):
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise ToolError(
                f"waivers[{index}] must contain exactly control_id, owner, reason, approval_reference, expires_at, compensating_control, and residual_risk."
            )
        control_id = str(raw.get("control_id") or "").strip()
        if control_id not in selected:
            raise ToolError(f"waivers[{index}].control_id is not selected.")
        if control_id in result:
            raise ToolError(f"Duplicate waiver for launch control: {control_id}")
        control = selected[control_id]
        if control["effectiveGateLevel"] == "blocker" or not control["waivable"]:
            raise ToolError(f"Launch control '{control_id}' may not be waived.")
        owner = _launch_safe_text(raw.get("owner"), f"waivers[{index}].owner", maximum=200)
        reason = _launch_safe_text(
            raw.get("reason"),
            f"waivers[{index}].reason",
            minimum=10,
            maximum=1_000,
        )
        reference = _launch_safe_text(
            raw.get("approval_reference"),
            f"waivers[{index}].approval_reference",
            maximum=500,
        )
        compensating = _launch_safe_text(
            raw.get("compensating_control"),
            f"waivers[{index}].compensating_control",
            minimum=10,
            maximum=1_000,
        )
        residual = _launch_safe_text(
            raw.get("residual_risk"),
            f"waivers[{index}].residual_risk",
            minimum=10,
            maximum=1_000,
        )
        try:
            expires = _dt.datetime.fromisoformat(
                str(raw.get("expires_at") or "").replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ToolError(
                f"waivers[{index}].expires_at must be an ISO-8601 timestamp with timezone."
            ) from exc
        if expires.tzinfo is None:
            raise ToolError(f"waivers[{index}].expires_at must include a timezone.")
        expires = expires.astimezone(_dt.timezone.utc)
        if not now < expires <= now + _dt.timedelta(days=30):
            raise ToolError(
                f"waivers[{index}].expires_at must be in the future and no more than 30 days away."
            )
        record_subject = {
            "controlId": control_id,
            "owner": owner,
            "reason": reason,
            "approvalReference": reference,
            "expiresAt": expires.replace(microsecond=0).isoformat(),
            "compensatingControl": compensating,
            "residualRisk": residual,
        }
        result[control_id] = {
            "controlId": control_id,
            "owner": owner,
            "expiresAt": record_subject["expiresAt"],
            "recordDigest": hashlib.sha256(
                json.dumps(
                    record_subject,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
    return result


def tool_launch_finalize(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    session_token = str(args.get("launch_session_token") or "").strip()
    session, subject, policy, selection = _launch_session_payload(
        project_path,
        session_token,
    )
    raw_receipts = args.get("evidence_receipts")
    if not isinstance(raw_receipts, list) or len(raw_receipts) > LAUNCH_MAX_RECEIPTS:
        raise ToolError("evidence_receipts must be an array of at most 100 receipts.")
    if any(
        not isinstance(receipt, str)
        or not receipt
        or len(receipt) > LAUNCH_MAX_RECEIPT_CHARS
        for receipt in raw_receipts
    ):
        raise ToolError("Each launch evidence receipt must be a bounded non-empty string.")
    if len(raw_receipts) != len(set(raw_receipts)):
        raise ToolError("evidence_receipts must not contain duplicate receipt values.")
    selected = {
        str(control["id"]): control for control in selection["selectedControls"]
    }
    waivers = _launch_waivers(
        args.get("waivers"),
        selected=selected,
        policy=policy,
    )
    evidence_by_control: dict[str, dict[str, Any]] = {}
    evidence_receipt_digests: dict[str, str] = {}
    receipt_verification: list[dict[str, Any]] = []
    blockers: list[str] = []
    warnings: list[str] = []
    session_digest = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    now = _dt.datetime.now(_dt.timezone.utc)
    evidence_expiries: list[_dt.datetime] = []
    for index, receipt in enumerate(raw_receipts):
        try:
            verification = verify_receipt(
                receipt,
                "launch-evidence",
                subject,
                expected_subject=subject,
                require_passed=False,
            )
        except ToolError:
            blockers.append(f"Launch evidence receipt {index + 1} is malformed or unsigned.")
            continue
        payload = verification["payload"]
        control_id = str(payload.get("controlId") or "")
        control = selected.get(control_id)
        contract_checks = {
            "receipt": verification["valid"],
            "schemaVersion": payload.get("schemaVersion")
            == "jstack.launch.evidence.v1",
            "selectedControl": control is not None,
            "catalogVersion": payload.get("catalogVersion")
            == selection["catalogVersion"],
            "catalogDigest": payload.get("catalogDigest")
            == selection["catalogDigest"],
            "selectionDigest": payload.get("selectionDigest")
            == selection["selectionDigest"],
            "session": payload.get("launchSessionDigest") == session_digest,
        }
        if control is not None:
            contract_checks.update(
                {
                    "category": payload.get("category") == control["category"],
                    "gateLevel": payload.get("gateLevel")
                    == control["effectiveGateLevel"],
                    "evidenceKind": payload.get("evidenceKind")
                    in control["evidenceKinds"],
                    "outcome": payload.get("outcome")
                    in {"pass", "fail", "incomplete", "not-applicable"},
                    "notApplicableAllowed": payload.get("outcome")
                    != "not-applicable"
                    or control["allowNotApplicable"],
                }
            )
        artifact_shape = (
            isinstance(payload.get("artifactSha256"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", payload["artifactSha256"]))
            and isinstance(payload.get("artifactSize"), int)
            and not isinstance(payload.get("artifactSize"), bool)
            and 0 <= payload["artifactSize"] <= LAUNCH_MAX_ARTIFACT_BYTES
        )
        contract_checks["artifactIdentity"] = artifact_shape
        valid = all(contract_checks.values())
        receipt_verification.append(
            {
                "index": index,
                "controlId": control_id or None,
                "valid": valid,
                "checks": contract_checks,
            }
        )
        if not valid:
            blockers.append(
                f"Launch evidence receipt {index + 1} does not match the current launch contract."
            )
            continue
        if control_id in evidence_by_control:
            blockers.append(
                f"Multiple launch evidence receipts target control '{control_id}'; provide exactly one current outcome."
            )
            continue
        evidence_by_control[control_id] = payload
        evidence_receipt_digests[control_id] = hashlib.sha256(
            receipt.encode("utf-8")
        ).hexdigest()
        try:
            evidence_expiry = _dt.datetime.fromisoformat(str(payload["expiresAt"]))
            if evidence_expiry.tzinfo is None:
                raise ValueError("timezone")
            evidence_expiries.append(evidence_expiry.astimezone(_dt.timezone.utc))
        except (KeyError, ValueError):
            blockers.append(f"Launch evidence for '{control_id}' has no valid expiry.")

    control_results: list[dict[str, Any]] = []
    for control in selection["selectedControls"]:
        control_id = str(control["id"])
        gate_level = str(control["effectiveGateLevel"])
        evidence = evidence_by_control.get(control_id)
        waiver = waivers.get(control_id)
        if waiver:
            status = "waived"
            control_results.append(
                {
                    "controlId": control_id,
                    "sequence": control["sequence"],
                    "category": control["category"],
                    "gateLevel": gate_level,
                    "status": status,
                    "evidenceReceiptDigest": evidence_receipt_digests.get(
                        control_id
                    ),
                    "waiverDigest": waiver["recordDigest"],
                }
            )
            continue
        if evidence is None:
            status = "incomplete"
            message = f"Launch control '{control_id}' has no current evidence."
            if gate_level in {"blocker", "required"}:
                blockers.append(message)
            else:
                warnings.append(message)
            evidence_digest = None
        else:
            status = str(evidence["outcome"])
            evidence_digest = evidence_receipt_digests[control_id]
            if status in {"fail", "incomplete"}:
                message = (
                    f"Launch control '{control_id}' has outcome '{status}'."
                )
                if gate_level in {"blocker", "required"}:
                    blockers.append(message)
                else:
                    warnings.append(message)
        control_results.append(
            {
                "controlId": control_id,
                "sequence": control["sequence"],
                "category": control["category"],
                "gateLevel": gate_level,
                "status": status,
                "evidenceReceiptDigest": evidence_digest,
                "waiverDigest": None,
            }
        )

    blockers = list(dict.fromkeys(blockers))
    warnings = list(dict.fromkeys(warnings))
    ready = not blockers
    expiry_candidates = [
        now + _dt.timedelta(seconds=LAUNCH_RECEIPT_MAX_AGE_SECONDS),
        *evidence_expiries,
        *(
            _dt.datetime.fromisoformat(waiver["expiresAt"])
            for waiver in waivers.values()
        ),
    ]
    expires = min(expiry_candidates).astimezone(_dt.timezone.utc).replace(
        microsecond=0
    )
    launch_receipt = issue_receipt(
        {
            "kind": "launch",
            "schemaVersion": "jstack.launch.receipt.v1",
            "projectPath": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "baseRef": subject["baseRef"],
            "baseCommit": subject["baseCommit"],
            "policyDigest": subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "catalogVersion": selection["catalogVersion"],
            "catalogDigest": selection["catalogDigest"],
            "selectionDigest": selection["selectionDigest"],
            "targetEnvironment": session["targetEnvironment"],
            "targetUrl": session.get("targetUrl"),
            "surfaces": selection["surfaces"],
            "profileOwner": session["profileOwner"],
            "profileReferenceDigest": session["profileReferenceDigest"],
            "controlResults": control_results,
            "activeWaivers": list(waivers.values()),
            "complete": ready,
            "passed": ready,
            "expiresAt": expires.isoformat(),
        }
    )
    return {
        "schemaVersion": "jstack.launch.finalization.v1",
        "projectPath": str(project_path),
        "targetEnvironment": session["targetEnvironment"],
        "targetUrl": session.get("targetUrl"),
        "surfaces": selection["surfaces"],
        "ready": ready,
        "complete": ready,
        "passed": ready,
        "executionAuthorized": False,
        "blockers": blockers,
        "warnings": warnings,
        "controlResults": control_results,
        "waivers": list(waivers.values()),
        "receiptVerification": receipt_verification,
        "launchReceipt": launch_receipt,
        "expiresAt": expires.isoformat(),
        "attestationLimit": "The receipt proves current contract-bound evidence records and named attestations, not independent semantic truth or legal certification.",
        "externalActionBoundary": {
            "launchReadyIsNotAuthority": True,
            "protectedActions": list(authorization_core.ACTIONS),
        },
    }


def tool_release_readiness(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    base_ref = str(args.get("base_ref") or "").strip()
    target_environment = _launch_environment(args.get("target_environment"))
    explicit_release_requested = bool(args.get("explicit_release_requested") or False)
    rollback_plan = str(args.get("rollback_plan") or "").strip()
    monitoring_plan = str(args.get("monitoring_plan") or "").strip()
    canary_plan = str(args.get("canary_plan") or "").strip()
    approved_by = str(args.get("approved_by") or "").strip()
    approval_reference = str(args.get("approval_reference") or "").strip()
    security_reviewed_by = str(args.get("security_reviewed_by") or "").strip()
    preflight_args = dict(args)
    preflight_args["strict"] = True
    preflight_args["target_environment"] = target_environment
    preflight_args["explicit_release_requested"] = explicit_release_requested
    preflight = tool_preflight(preflight_args)
    ship = tool_ship_check(
        {
            "project_path": str(project_path),
            "base_ref": base_ref,
            "qa_receipts": args.get("qa_receipts") or [],
        }
    )
    blockers = list(preflight["blockers"]) + list(ship["blockers"])
    warnings = list(preflight["warnings"])
    subject = evidence_subject(project_path, base_ref or None)
    if not base_ref:
        blockers.append("Release readiness requires an explicit base_ref; automatic upstream discovery is not an approval boundary.")
    elif subject["baseCommit"] == subject["gitHead"]:
        blockers.append("Release base_ref must resolve to a distinct pre-release commit; HEAD cannot be its own baseline.")
    if not subject["clean"]:
        blockers.append("Release readiness requires a clean committed working tree; commit or remove local changes, then rerun all evidence checks.")

    qa_receipts = args.get("qa_receipts") or []
    if not isinstance(qa_receipts, list) or not all(isinstance(item, str) for item in qa_receipts):
        raise ToolError("qa_receipts must be an array of receipts returned by jstack_qa.")
    required_commands = discover_test_commands(project_path)
    verified_qa: list[dict[str, Any]] = []
    receipt_by_key: dict[str, dict[str, Any]] = {}
    for receipt in qa_receipts:
        verification = verify_receipt(receipt, "qa", subject, expected_subject=subject)
        verified_qa.append(verification)
        payload = verification["payload"]
        command_key = str(payload.get("commandKey") or "")
        if verification["valid"] and command_key:
            receipt_by_key[command_key] = payload
    for command in required_commands:
        payload = receipt_by_key.get(command["key"])
        if not payload:
            blockers.append(f"Missing a current passing QA receipt for discovered command '{command['key']}'.")
        elif payload.get("commandFingerprint") != command["commandFingerprint"]:
            blockers.append(f"QA receipt for '{command['key']}' does not match the currently discovered command definition.")
    if not required_commands:
        blockers.append("No test/lint/typecheck/build commands were discovered; release readiness cannot be established.")

    security_receipt = str(args.get("security_receipt") or "").strip()
    if not security_receipt and preflight.get("securitySummary"):
        security_receipt = str(preflight["securitySummary"].get("evidenceReceipt") or "")
    verified_security: Optional[dict[str, Any]] = None
    if security_receipt:
        verified_security = verify_receipt(security_receipt, "security", subject, expected_subject=subject)
        if not verified_security["valid"]:
            blockers.append("Security evidence receipt is not a current, complete, clean result for this commit and project state.")
    else:
        blockers.append("Release readiness requires a current security evidence receipt.")

    enterprise_policy = load_enterprise_policy(project_path)
    launch_policy = enterprise_policy.get("launch", {})
    launch_required = bool(
        target_environment == "production"
        and launch_policy.get("requireReceiptForProduction", True)
    )
    launch_receipt = str(args.get("launch_receipt") or "").strip()
    verified_launch: Optional[dict[str, Any]] = None
    launch_passes_release = False
    release_audit_surfaces: list[str] = []
    if launch_receipt:
        if len(launch_receipt) > LAUNCH_MAX_RECEIPT_CHARS:
            raise ToolError("launch_receipt exceeds the bounded receipt size.")
        verified_launch = verify_receipt(
            launch_receipt,
            "launch",
            subject,
            expected_subject=subject,
            require_passed=False,
        )
        launch_payload = verified_launch.get("payload") or {}
        try:
            receipt_selection = _launch_call(
                lambda: launch_core.select_controls(
                    list(launch_payload.get("surfaces") or []),
                    target_environment=str(
                        launch_payload.get("targetEnvironment") or ""
                    ),
                    target_url=launch_payload.get("targetUrl"),
                    required_control_ids=launch_policy.get(
                        "requiredControlIds", []
                    ),
                    advisory_control_ids=launch_policy.get(
                        "advisoryControlIds", []
                    ),
                )
            )
            launch_contract_current = (
                launch_payload.get("catalogVersion")
                == receipt_selection["catalogVersion"]
                and launch_payload.get("catalogDigest")
                == receipt_selection["catalogDigest"]
                and launch_payload.get("selectionDigest")
                == receipt_selection["selectionDigest"]
                and launch_payload.get("surfaces")
                == receipt_selection["surfaces"]
            )
        except ToolError:
            receipt_selection = None
            launch_contract_current = False
        launch_passes_release = (
            verified_launch["valid"]
            and launch_payload.get("schemaVersion")
            == "jstack.launch.receipt.v1"
            and launch_payload.get("complete") is True
            and launch_payload.get("passed") is True
            and launch_payload.get("targetEnvironment") == target_environment
            and launch_contract_current
        )
        if launch_required and not launch_passes_release:
            blockers.append(
                "Production release requires a current complete passing launch-assurance receipt for this exact release candidate and environment."
            )
        elif not launch_passes_release:
            warnings.append(
                "An optional launch-assurance receipt was supplied but is not current, complete, passing, or environment-matched."
            )
        if launch_passes_release and receipt_selection is not None:
            release_audit_surfaces = sorted(
                set(receipt_selection["surfaces"])
                & set(
                    launch_policy.get("requireReleaseAuditForSurfaces", [])
                )
            )
    elif launch_required:
        blockers.append(
            "Production release requires a current complete passing launch-assurance receipt from jstack_launch_finalize."
        )

    audit_policy = enterprise_policy.get("audit", {})
    audit_required = bool(
        audit_policy.get("releaseRequiresAuditReceipt")
        or release_audit_surfaces
    )
    audit_receipt = str(args.get("audit_receipt") or "").strip()
    verified_audit: Optional[dict[str, Any]] = None
    if audit_receipt:
        verified_audit = verify_receipt(
            audit_receipt,
            "audit",
            subject,
            expected_subject=subject,
            require_passed=False,
        )
        audit_payload = verified_audit.get("payload") or {}
        active_suppressions = audit_payload.get("activeSuppressions") or []
        suppressions_current = isinstance(active_suppressions, list)
        if suppressions_current:
            now_utc = _dt.datetime.now(_dt.timezone.utc)
            for suppression in active_suppressions:
                try:
                    expiry = _dt.datetime.fromisoformat(
                        str(suppression["expiresAt"]).replace("Z", "+00:00")
                    )
                    if expiry.tzinfo is None or expiry.astimezone(_dt.timezone.utc) <= now_utc:
                        raise ValueError("expired suppression")
                except (KeyError, TypeError, ValueError):
                    suppressions_current = False
                    break
        expected_release_range_digest = audit_release_range_digest(
            project_path,
            str(subject.get("baseCommit") or "").strip() or None,
        )
        audit_passes_release = (
            verified_audit["valid"]
            and audit_payload.get("passed") is True
            and audit_payload.get("complete") is True
            and audit_payload.get("resultStatus") == "pass"
            and audit_payload.get("profile") == str(audit_policy.get("releaseProfile") or "release")
            and audit_payload.get("scopeMode") == "repository"
            and audit_payload.get("scope") == ["."]
            and audit_payload.get("releaseScopeCovered") is True
            and audit_payload.get("releaseRangeDigest") == expected_release_range_digest
            and suppressions_current
        )
        if audit_required and not audit_passes_release:
            blockers.append("Release policy requires a current complete passing release-profile audit receipt.")
        elif not audit_passes_release:
            warnings.append("An optional audit receipt was supplied but is not a current complete passing release-profile result.")
    elif audit_required:
        blockers.append("Release policy requires a current complete passing release-profile audit receipt.")

    if not explicit_release_requested:
        blockers.append(
            "Release readiness requires an explicit user request for this evidence assessment. This flag never authorizes a release action."
        )
    if target_environment in {"production", "prod"} and not approved_by:
        blockers.append("Production release requires an approver name or approval reference.")
    if target_environment in {"production", "prod"} and not approval_reference:
        blockers.append("Production release requires an environment-specific approval reference from outside the MCP.")
    if target_environment in {"production", "prod"} and not rollback_plan:
        blockers.append("Production release requires a rollback plan.")
    if target_environment in {"production", "prod"} and not (monitoring_plan or canary_plan):
        blockers.append("Production release requires a monitoring or canary plan.")
    if goal_is_sensitive(str(args.get("goal") or ""), enterprise_policy) and not security_reviewed_by:
        blockers.append("Sensitive release work requires a named human security reviewer or review reference.")

    return {
        "projectPath": str(project_path),
        "targetEnvironment": target_environment,
        "ready": not blockers,
        "executionAuthorized": False,
        "blockers": list(dict.fromkeys(blockers)),
        "warnings": warnings,
        "approval": {
            "explicitReleaseRequested": explicit_release_requested,
            "meaning": "Request to assess readiness only; never external-action authority.",
            "approvedBy": approved_by,
            "approvalReference": approval_reference,
            "securityReviewedBy": security_reviewed_by,
        },
        "plans": {
            "rollbackPlan": rollback_plan,
            "monitoringPlan": monitoring_plan,
            "canaryPlan": canary_plan,
        },
        "evidenceState": subject,
        "qaEvidence": {
            "requiredCommands": required_commands,
            "verifiedReceipts": verified_qa,
        },
        "securityEvidence": verified_security,
        "launchEvidence": {
            "required": launch_required,
            "verification": verified_launch,
            "passesRelease": launch_passes_release,
            "releaseAuditRequiredBySurfaces": release_audit_surfaces,
        },
        "auditEvidence": {
            "required": audit_required,
            "requiredByLaunchSurfaces": release_audit_surfaces,
            "verification": verified_audit,
        },
        "preflight": preflight,
        "shipCheck": ship,
        "releaseStandard": [
            "No unresolved blockers.",
            "Tests and security checks are evidenced or explicitly blocked.",
            "Applicable launch controls are resolved by current typed evidence, explicit not-applicable proof, or a bounded non-blocker waiver.",
            "Rollback and monitoring are documented before production.",
            "Every commit, push, pull request, merge, tag, release, deployment, or production mutation separately consumes its own exact JStack external-action permit.",
        ],
        "externalActionBoundary": {
            "defaultMode": "local-only",
            "readinessIsNotAuthority": True,
            "protectedActions": list(authorization_core.ACTIONS),
            "requiredTools": [
                "jstack_external_action_challenge",
                "jstack_external_action_authorize",
                "jstack_external_action_consume",
            ],
        },
    }


def parse_backtest_report(report_path: Path) -> dict[str, Any]:
    text = report_path.read_text(encoding="utf-8", errors="ignore")
    compact = re.sub(r"\s+", " ", text)
    metrics: dict[str, Any] = {
        "path": str(report_path),
        "historyQualityPercent": percentage_from_text(compact, ["History Quality", "Modelling quality", "Modeling quality"]),
    }
    metric_patterns = {
        "totalNetProfit": r"Total Net Profit[^-0-9]{0,80}(-?[0-9][0-9,]*(?:\.[0-9]+)?)",
        "profitFactor": r"Profit Factor[^0-9]{0,80}([0-9]+(?:\.[0-9]+)?)",
        "totalTrades": r"Total Trades[^0-9]{0,80}([0-9]+)",
        "maxDrawdown": r"(?:Maximal drawdown|Equity Drawdown Maximal|Balance Drawdown Maximal)[^-0-9]{0,80}(-?[0-9][0-9,]*(?:\.[0-9]+)?)",
    }
    for key, pattern in metric_patterns.items():
        match = re.search(pattern, compact, re.IGNORECASE)
        if not match:
            continue
        raw_value = match.group(1).replace(",", "")
        try:
            metrics[key] = float(raw_value) if "." in raw_value else int(raw_value)
        except ValueError:
            metrics[key] = raw_value
    return metrics


def tool_quant_backtest_review(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    evidence = args.get("evidence") or {}
    if not isinstance(evidence, dict):
        raise ToolError("evidence must be an object when provided.")
    strict = bool(args.get("strict", True))
    report_path_raw = str(args.get("report_path") or evidence.get("report_path") or "").strip()
    report_metrics: Optional[dict[str, Any]] = None
    warnings: list[str] = []
    blockers: list[str] = []
    if report_path_raw:
        report_path = Path(report_path_raw).expanduser()
        if not report_path.is_absolute():
            report_path = project_path / report_path
        if report_path.is_symlink():
            blockers.append(f"Backtest report may not be a symlink: {report_path}")
        elif not report_path.exists():
            blockers.append(f"Backtest report path does not exist: {report_path}")
        elif not report_path.is_file():
            blockers.append(f"Backtest report must be a regular file: {report_path}")
        elif report_path.stat().st_size > 10_000_000:
            blockers.append("Backtest report exceeds the 10 MB review limit.")
        else:
            resolved_report = report_path.resolve()
            try:
                resolved_report.relative_to(project_path)
            except ValueError:
                blockers.append("Backtest report must be inside the reviewed project directory.")
            else:
                report_metrics = parse_backtest_report(resolved_report)
    elif strict:
        blockers.append("Strict quant review requires a backtest report path.")

    policy = load_enterprise_policy(project_path)
    quant_policy = policy.get("quant", {})
    required = [str(item) for item in quant_policy.get("requiredEvidence", [])]
    key_aliases = {
        "date_range": ["date_range", "start_date", "end_date"],
        "history_quality_or_modelling_quality": ["history_quality", "modelling_quality", "modeling_quality"],
        "settings_file": ["settings_file", "set_file", "ini_file"],
        "source_version": ["source_version", "ea_version", "git_commit"],
        "in_sample_out_of_sample_split": ["in_sample_out_of_sample_split", "oos_split", "out_of_sample"],
        "walk_forward_or_forward_test_plan": ["walk_forward", "forward_test_plan"],
        "drawdown_stress_test": ["drawdown_stress_test", "monte_carlo", "stress_test"],
        "no_lookahead_bias_review": ["no_lookahead_bias_review", "lookahead_bias_review"],
    }
    missing: list[str] = []
    for item in required:
        aliases = key_aliases.get(item, [item])
        report_satisfies = item == "history_quality_or_modelling_quality" and report_metrics is not None and report_metrics.get("historyQualityPercent") is not None
        if not report_satisfies and not any(evidence.get(alias) not in (None, "", False, []) for alias in aliases):
            missing.append(item)
    if missing:
        blockers.append("Missing required quant/backtest evidence: " + ", ".join(missing))

    min_quality = float(quant_policy.get("minimumHistoryQualityPercent") or 99.0)
    supplied_quality = evidence.get("history_quality") or evidence.get("modelling_quality") or evidence.get("modeling_quality")
    detected_quality = report_metrics.get("historyQualityPercent") if report_metrics else None
    quality_value = detected_quality if detected_quality is not None else supplied_quality
    if detected_quality is not None and supplied_quality is not None:
        try:
            if float(str(supplied_quality).replace("%", "")) != float(detected_quality):
                blockers.append("Supplied history/modelling quality conflicts with the parsed report; parsed report evidence takes precedence.")
        except ValueError:
            blockers.append("Supplied history/modelling quality is not numeric and conflicts with parsed report evidence.")
    if quality_value is not None:
        try:
            quality_float = float(str(quality_value).replace("%", ""))
            if quality_float < min_quality:
                blockers.append(f"History/modelling quality {quality_float}% is below policy minimum {min_quality}%.")
        except ValueError:
            warnings.append(f"Could not parse history/modelling quality value: {quality_value}")
    elif strict:
        blockers.append("No history/modelling quality value was supplied or detected.")

    if report_metrics:
        if strict:
            missing_metrics = [
                key for key in ("historyQualityPercent", "totalTrades", "profitFactor", "totalNetProfit")
                if report_metrics.get(key) is None
            ]
            if missing_metrics:
                blockers.append("Backtest report is missing required parsed metrics: " + ", ".join(missing_metrics))
        if report_metrics.get("totalTrades") == 0:
            blockers.append("Backtest report shows zero trades.")
        if isinstance(report_metrics.get("totalNetProfit"), (int, float)) and report_metrics["totalNetProfit"] < 0:
            warnings.append("Backtest report appears unprofitable; do not optimize until the failure mode is diagnosed.")
        if isinstance(report_metrics.get("profitFactor"), (int, float)) and report_metrics["profitFactor"] < 1.0:
            warnings.append("Profit factor is below 1.0; strategy edge is not demonstrated on this sample.")

    return {
        "projectPath": str(project_path),
        "policySource": policy.get("_sourcePath"),
        "readyForProductionClaim": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "requiredEvidence": required,
        "missingEvidence": missing,
        "evidence": evidence,
        "reportMetrics": report_metrics,
        "quantReviewStandard": [
            "No production or investor-facing claim without reproducible report files.",
            "Separate in-sample, out-of-sample, and forward-test evidence.",
            "Document spread, commission, slippage, symbol contract specs, and data source.",
            "Freeze parameters before out-of-sample or forward validation.",
            "Reject results with lookahead bias, hidden optimization, missing cost model, or poor history quality.",
        ],
    }


def _loop_service(project_path: Path) -> loop_core.LoopService:
    return loop_core.LoopService(Path.home(), project_path)


def _loop_call(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return operation()
    except loop_core.LoopError as exc:
        raise ToolError(str(exc)) from exc


def git_worktree_attestation(project_path: Path) -> dict[str, Any]:
    git_dir_result = run_complete(["git", "rev-parse", "--git-dir"], project_path, timeout=8)
    common_dir_result = run_complete(["git", "rev-parse", "--git-common-dir"], project_path, timeout=8)
    if not git_dir_result["ok"] or not common_dir_result["ok"]:
        raise ToolError("Could not attest the Git worktree layout for loop autonomy.")

    def resolved(raw: str) -> Path:
        candidate = Path(raw.strip())
        if not candidate.is_absolute():
            candidate = project_path / candidate
        return candidate.resolve()

    git_dir = resolved(_git_text(git_dir_result))
    common_dir = resolved(_git_text(common_dir_result))
    return {
        "isLinkedWorktree": git_dir != common_dir,
        "gitDirDigest": hashlib.sha256(str(git_dir).encode("utf-8")).hexdigest(),
        "commonDirDigest": hashlib.sha256(str(common_dir).encode("utf-8")).hexdigest(),
    }


def stable_loop_contract_context(
    project_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    subject_before = evidence_subject(project_path)
    policy = load_enterprise_policy(project_path)
    worktree = git_worktree_attestation(project_path)
    subject_after = evidence_subject(project_path)
    if any(
        subject_after[field] != subject_before[field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed while the loop contract context was being collected. Re-run against one stable Git state."
        )
    return subject_after, policy, worktree


def _receipt_digest(receipt: str) -> str:
    return hashlib.sha256(receipt.encode("utf-8")).hexdigest()


def _reject_loop_secret_inputs(args: dict[str, Any]) -> None:
    receipt_fields = {
        "qa_receipts",
        "security_receipt",
        "audit_receipts",
        "launch_receipt",
        "specialist_handoff_receipt",
        "goal_readiness_receipt",
        "program_readiness_receipt",
        "loop_completion_receipt",
        "approval_attestation",
    }

    def visit(value: Any, field: str) -> None:
        if field in receipt_fields:
            return
        if isinstance(value, str):
            if audit_core.contains_secret_like(value):
                raise ToolError(
                    "Loop input contains a secret-like value. Remove it, use only a redacted external reference, and revoke it first if it was exposed."
                )
            return
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, str(key))
        elif isinstance(value, list):
            for child in value:
                visit(child, field)

    visit(args, "arguments")


def _loop_receipt_evidence(
    args: dict[str, Any],
    subject: dict[str, Any],
    capability_contract: Optional[dict[str, Any]] = None,
    expected_goal_digest: Optional[str] = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    evidence: dict[str, Any] = {"qa": [], "audit": []}
    invalid: list[dict[str, Any]] = []

    qa_receipts = args.get("qa_receipts") or []
    if not isinstance(qa_receipts, list) or not all(isinstance(item, str) for item in qa_receipts):
        raise ToolError("qa_receipts must be an array of receipts returned by jstack_qa.")
    if len(qa_receipts) > LOOP_MAX_QA_RECEIPTS or any(
        len(item) > LOOP_MAX_RECEIPT_CHARS for item in qa_receipts
    ):
        raise ToolError("qa_receipts exceeds the bounded loop evidence limits.")
    seen_qa: set[str] = set()
    for receipt in qa_receipts:
        digest = _receipt_digest(receipt)
        if digest in seen_qa:
            continue
        seen_qa.add(digest)
        try:
            verification = verify_receipt(receipt, "qa", subject, expected_subject=subject)
        except ToolError:
            invalid.append({"kind": "qa", "receiptDigest": digest, "reason": "malformed-or-wrong-session"})
            continue
        if not verification["valid"]:
            invalid.append(
                {
                    "kind": "qa",
                    "receiptDigest": digest,
                    "checks": verification["checks"],
                }
            )
            continue
        payload = verification["payload"]
        evidence["qa"].append(
            {
                "type": "qa-receipt",
                "commandKey": payload.get("commandKey"),
                "commandFingerprint": payload.get("commandFingerprint"),
                "receiptDigest": digest,
                "passed": True,
            }
        )

    security_receipt = str(args.get("security_receipt") or "").strip()
    if len(security_receipt) > LOOP_MAX_RECEIPT_CHARS:
        raise ToolError("security_receipt exceeds the bounded loop evidence limit.")
    if security_receipt:
        digest = _receipt_digest(security_receipt)
        try:
            verification = verify_receipt(
                security_receipt, "security", subject, expected_subject=subject
            )
        except ToolError:
            invalid.append(
                {"kind": "security", "receiptDigest": digest, "reason": "malformed-or-wrong-session"}
            )
        else:
            if verification["valid"]:
                payload = verification["payload"]
                evidence["security"] = {
                    "type": "security-receipt",
                    "receiptDigest": digest,
                    "findingCount": payload.get("findingCount"),
                    "complete": payload.get("complete") is True,
                    "passed": True,
                }
            else:
                invalid.append(
                    {
                        "kind": "security",
                        "receiptDigest": digest,
                        "checks": verification["checks"],
                    }
                )

    audit_receipts = args.get("audit_receipts") or []
    if not isinstance(audit_receipts, list) or not all(isinstance(item, str) for item in audit_receipts):
        raise ToolError("audit_receipts must be an array of receipts returned by jstack_audit_finalize.")
    if len(audit_receipts) > LOOP_MAX_AUDIT_RECEIPTS or any(
        len(item) > LOOP_MAX_RECEIPT_CHARS for item in audit_receipts
    ):
        raise ToolError("audit_receipts exceeds the bounded loop evidence limits.")
    seen_audit: set[str] = set()
    for receipt in audit_receipts:
        digest = _receipt_digest(receipt)
        if digest in seen_audit:
            continue
        seen_audit.add(digest)
        try:
            verification = verify_receipt(receipt, "audit", subject, expected_subject=subject)
        except ToolError:
            invalid.append({"kind": "audit", "receiptDigest": digest, "reason": "malformed-or-wrong-session"})
            continue
        if not verification["valid"]:
            invalid.append(
                {
                    "kind": "audit",
                    "receiptDigest": digest,
                    "checks": verification["checks"],
                }
            )
            continue
        payload = verification["payload"]
        evidence["audit"].append(
            {
                "type": "audit-receipt",
                "profile": payload.get("profile"),
                "receiptDigest": digest,
                "coverageDigest": payload.get("coverageDigest"),
                "findingDigest": payload.get("findingDigest"),
                "complete": payload.get("complete") is True,
                "passed": True,
            }
        )

    launch_receipt = str(args.get("launch_receipt") or "").strip()
    if len(launch_receipt) > LOOP_MAX_RECEIPT_CHARS:
        raise ToolError("launch_receipt exceeds the bounded loop evidence limit.")
    if launch_receipt:
        digest = _receipt_digest(launch_receipt)
        try:
            verification = verify_receipt(
                launch_receipt,
                "launch",
                subject,
                expected_subject=subject,
            )
        except ToolError:
            invalid.append(
                {
                    "kind": "launch",
                    "receiptDigest": digest,
                    "reason": "malformed-or-wrong-session",
                }
            )
        else:
            payload = verification["payload"]
            launch_policy = load_enterprise_policy(
                Path(subject["gitRoot"])
            ).get("launch", {})
            try:
                environment = _launch_environment(
                    payload.get("targetEnvironment")
                )
                surfaces = _launch_call(
                    lambda: launch_core.normalize_surfaces(
                        list(payload.get("surfaces") or [])
                    )
                )
                selection = _launch_call(
                    lambda: launch_core.select_controls(
                        surfaces,
                        target_environment=environment,
                        target_url=payload.get("targetUrl"),
                        required_control_ids=launch_policy.get(
                            "requiredControlIds", []
                        ),
                        advisory_control_ids=launch_policy.get(
                            "advisoryControlIds", []
                        ),
                    )
                )
                contract_checks = {
                    "schemaVersion": payload.get("schemaVersion")
                    == "jstack.launch.receipt.v1",
                    "complete": payload.get("complete") is True,
                    "passed": payload.get("passed") is True,
                    "targetEnvironment": payload.get("targetEnvironment")
                    == environment,
                    "surfaces": payload.get("surfaces") == surfaces,
                    "catalogVersion": payload.get("catalogVersion")
                    == selection["catalogVersion"],
                    "catalogDigest": payload.get("catalogDigest")
                    == selection["catalogDigest"],
                    "selectionDigest": payload.get("selectionDigest")
                    == selection["selectionDigest"],
                }
            except ToolError:
                environment = None
                surfaces = []
                selection = None
                contract_checks = {"launchContract": False}
            if verification["valid"] and all(contract_checks.values()):
                evidence["launch"] = {
                    "type": "launch-receipt",
                    "receiptDigest": digest,
                    "targetEnvironment": environment,
                    "surfaces": surfaces,
                    "selectionDigest": selection["selectionDigest"],
                    "complete": True,
                    "passed": True,
                }
            else:
                invalid.append(
                    {
                        "kind": "launch",
                        "receiptDigest": digest,
                        "checks": {
                            **verification["checks"],
                            **contract_checks,
                        },
                    }
                )
    specialist_handoff_receipt = str(
        args.get("specialist_handoff_receipt") or ""
    ).strip()
    if len(specialist_handoff_receipt) > LOOP_MAX_RECEIPT_CHARS:
        raise ToolError(
            "specialist_handoff_receipt exceeds the bounded loop evidence limit."
        )
    if specialist_handoff_receipt:
        digest = _receipt_digest(specialist_handoff_receipt)
        try:
            verification = verify_receipt(
                specialist_handoff_receipt,
                "specialist-handoff",
                subject,
            )
        except ToolError:
            invalid.append(
                {
                    "kind": "specialist-handoff",
                    "receiptDigest": digest,
                    "reason": "malformed-or-wrong-session",
                }
            )
        else:
            payload = verification["payload"]
            capability_checks = {
                "schemaVersion": payload.get("schemaVersion")
                == "jstack.specialist.handoff-receipt.v1",
                "policyDigest": payload.get("policyDigest")
                == subject.get("policyDigest"),
                "toolVersion": payload.get("toolVersion")
                == subject.get("toolVersion"),
                "catalogDigest": capability_contract is None
                or payload.get("capabilityCatalogDigest")
                == capability_contract.get("catalogDigest"),
                "selectionDigest": capability_contract is None
                or payload.get("capabilitySelectionDigest")
                == capability_contract.get("selectionDigest"),
                "teamMode": capability_contract is None
                or payload.get("teamMode")
                == capability_contract.get("executionMode"),
                "teamRoleIds": capability_contract is None
                or payload.get("teamRoleIds")
                == capability_contract.get("teamRoleIds"),
                "goalDigest": expected_goal_digest is None
                or payload.get("goalDigest") == expected_goal_digest,
            }
            if verification["valid"] and all(capability_checks.values()):
                evidence["specialistHandoff"] = {
                    "type": "specialist-handoff-receipt",
                    "receiptDigest": digest,
                    "catalogDigest": payload.get("capabilityCatalogDigest"),
                    "selectionDigest": payload.get("capabilitySelectionDigest"),
                    "teamRoleIds": payload.get("teamRoleIds"),
                    "passed": True,
                }
            else:
                invalid.append(
                    {
                        "kind": "specialist-handoff",
                        "receiptDigest": digest,
                        "checks": {
                            **verification["checks"],
                            **capability_checks,
                        },
                    }
                )
    return evidence, invalid


def _loop_artifact_evidence(
    project_path: Path, acceptance_criteria: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    artifacts: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    total_limit = 100_000_000
    per_file_limit = 25_000_000
    deadline = time.monotonic() + 30
    for criterion in acceptance_criteria:
        verifier = criterion.get("verifier") or {}
        if verifier.get("type") != "artifact":
            continue
        relative = str(verifier.get("path") or "")
        if relative in seen:
            continue
        seen.add(relative)
        remaining_bytes = total_limit - total_bytes
        remaining_seconds = int(deadline - time.monotonic())
        if remaining_bytes <= 0 or remaining_seconds <= 0:
            artifacts.append({"type": "artifact", "path": relative, "exists": False})
            invalid.append({"kind": "artifact", "path": relative, "reason": "aggregate-limit"})
            continue
        try:
            size, digest = audit_core.digest_repository_file(
                project_path,
                relative,
                max_bytes=min(per_file_limit, remaining_bytes),
                max_seconds=max(1, remaining_seconds),
            )
        except audit_core.AuditError:
            artifacts.append({"type": "artifact", "path": relative, "exists": False})
            invalid.append({"kind": "artifact", "path": relative, "reason": "missing-or-unsafe"})
        else:
            total_bytes += size
            artifacts.append(
                {
                    "type": "artifact",
                    "path": relative,
                    "exists": True,
                    "size": size,
                    "sha256": digest,
                }
            )
    return artifacts, invalid


def _loop_iteration_evidence(
    project_path: Path,
    loop_status: dict[str, Any],
    args: dict[str, Any],
) -> dict[str, Any]:
    baseline = str(loop_status["baselineCommit"])
    subject = evidence_subject(project_path, baseline)
    change_evidence = git_change_evidence(project_path, baseline)
    if (
        subject.get("baseCommit") != baseline
        or change_evidence.get("baseCommit") != baseline
    ):
        raise ToolError(
            "The loop baseline is no longer the exact Git merge base of HEAD. Stop this loop and start a new contract after the branch, reset, or rebase is resolved."
        )
    changed_files = change_evidence["files"]
    policy = load_enterprise_policy(project_path)
    protected_patterns = [str(item) for item in policy.get("protectedPaths", [])]
    protected_files = [
        path for path in changed_files if path_matches_patterns(path, protected_patterns)
    ]
    capability_contract = loop_status.get("capabilityContract")
    if capability_contract is not None and not _loop_capability_contract_matches(
        loop_status
    ):
        raise ToolError(
            "The loop capability contract no longer matches the current catalog or "
            "deterministic routing. Run goal readiness and an approved material "
            "contract revision before continuing."
        )
    evidence, invalid = _loop_receipt_evidence(
        args,
        subject,
        capability_contract,
        hashlib.sha256(str(loop_status.get("goal") or "").encode("utf-8")).hexdigest(),
    )
    if (
        loop_status.get("executionMode") in {"smart-subagents", "full-team"}
        and not evidence.get("specialistHandoff")
    ):
        raise ToolError(
            "Multi-agent loop checkpoints and finalization require a current passed specialist_handoff_receipt bound to this capability contract and Git state."
        )
    review = tool_review({"project_path": str(project_path), "base_ref": baseline})
    evidence["review"] = {
        "type": "deterministic-review",
        "passed": review["diffCheck"]["returncode"] == 0
        and review.get("changeEvidence", {}).get("complete") is True,
        "diffCheckReturncode": review["diffCheck"]["returncode"],
        "changedFileCount": len(changed_files),
        "changeEvidenceComplete": review.get("changeEvidence", {}).get("complete") is True,
    }
    artifacts, artifact_invalid = _loop_artifact_evidence(
        project_path, loop_status["acceptanceCriteria"]
    )
    evidence["artifacts"] = artifacts
    evidence["invalid"] = [*invalid, *artifact_invalid]
    subject_after = evidence_subject(project_path, baseline)
    if any(
        subject_after[field] != subject[field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed while loop evidence was being collected. Re-run the checkpoint against one stable state."
        )
    return {
        "subject": subject_after,
        "policy": policy,
        "changedFiles": changed_files,
        "protectedFiles": protected_files,
        "evidence": evidence,
    }


def _verified_goal_readiness_attestation(
    receipt: Any, subject: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(receipt, str) or not receipt or len(receipt) > LOOP_MAX_RECEIPT_CHARS:
        raise ToolError(
            "A bounded goal_readiness_receipt returned by jstack_loop_goal_readiness is required."
        )
    verification = verify_receipt(
        receipt,
        "goal-readiness",
        subject,
        expected_subject=subject,
    )
    payload = verification["payload"]
    if (
        not verification["valid"]
        or payload.get("schemaVersion") != loop_core.GOAL_READINESS_RECEIPT_SCHEMA
    ):
        raise ToolError(
            "The goal-readiness receipt is stale, malformed, from another session, or bound to a different project state."
        )
    return {**payload, "receiptDigest": _receipt_digest(receipt)}


def _loop_capability_contract(
    goal: str,
    execution_mode: str,
    explicit_capability_ids: list[str],
) -> dict[str, Any]:
    _, team = _deterministic_specialist_team(
        goal, execution_mode, explicit_capability_ids
    )
    capability_plan = team["capabilityPlan"]
    assignments = capability_assignments_by_role(capability_plan)
    return {
        "schemaVersion": "jstack.loop.capability-contract.v1",
        "catalogVersion": capability_plan["catalogVersion"],
        "catalogDigest": capability_plan["catalogDigest"],
        "selectionDigest": capability_plan["selectionDigest"],
        "goalDigest": capability_plan["goalDigest"],
        "executionMode": execution_mode,
        "teamRoleIds": [str(agent["id"]) for agent in team["agents"]],
        "roleCapabilities": {
            str(agent["id"]): [
                str(item["capabilityId"])
                for item in assignments.get(str(agent["id"]), [])
            ]
            for agent in team["agents"]
        },
        "explicitCapabilityIds": list(explicit_capability_ids),
        "auditDomains": capability_plan["auditDomains"],
        "loopControls": capability_plan["loopControls"],
        "permissionInvariant": capability_plan["permissionInvariant"],
    }


def _loop_capability_contract_matches(loop_status: dict[str, Any]) -> Optional[bool]:
    capability_contract = loop_status.get("capabilityContract")
    if capability_contract is None:
        return None
    expected = _loop_capability_contract(
        str(loop_status.get("goal") or ""),
        str(loop_status.get("executionMode") or ""),
        [
            str(item)
            for item in capability_contract.get("explicitCapabilityIds") or []
        ],
    )
    return expected == capability_contract


def _loop_args_with_capabilities(
    args: dict[str, Any],
    prior_status: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    enriched = dict(args)
    goal = str(args.get("goal") or (prior_status or {}).get("goal") or "").strip()
    execution_mode = str(
        args.get("execution_mode")
        or (prior_status or {}).get("executionMode")
        or ""
    ).strip()
    if not goal or execution_mode not in {"single-lead", "smart-subagents", "full-team"}:
        return enriched
    prior_contract = (prior_status or {}).get("capabilityContract") or {}
    if "capability_ids" in args:
        raw_capability_ids = args.get("capability_ids") or []
    else:
        raw_capability_ids = prior_contract.get("explicitCapabilityIds") or []
    if not isinstance(raw_capability_ids, list):
        raise ToolError("capability_ids must be an array.")
    explicit_capability_ids = [str(item) for item in raw_capability_ids]
    enriched["goal"] = goal
    enriched["execution_mode"] = execution_mode
    enriched["capability_contract"] = _loop_capability_contract(
        goal, execution_mode, explicit_capability_ids
    )
    return enriched


def tool_loop_goal_readiness(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    subject, policy, worktree = stable_loop_contract_context(project_path)
    service = _loop_service(project_path)
    loop_id = str(args.get("loop_id") or "").strip() or None
    prior_contract_digest = None
    prior_status = None
    if loop_id:
        status = _loop_call(lambda: service.status(loop_id))
        if status["status"] in {"succeeded", "stopped"}:
            raise ToolError("Terminal loops cannot receive a revised goal-readiness receipt.")
        prior_contract_digest = status["contractDigest"]
        prior_status = status
    enriched_args = _loop_args_with_capabilities(args, prior_status)
    assessment = _loop_call(
        lambda: loop_core.assess_goal_readiness(
            enriched_args,
            project_root=str(project_path),
            subject=subject,
            worktree=worktree["isLinkedWorktree"],
            policy_source=policy.get("_sourcePath"),
            policy_digest=subject["policyDigest"],
            loop_id=loop_id,
            prior_contract_digest=prior_contract_digest,
        )
    )
    assessment.pop("_contract", None)
    if assessment.get("ready") is not True:
        assessment["receiptIssued"] = False
        return assessment
    subject_after = evidence_subject(project_path)
    if any(
        subject_after[field] != subject[field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed during goal-readiness assessment. Re-run the intake against one stable state."
        )
    expires_at = (
        _dt.datetime.now(_dt.timezone.utc)
        + _dt.timedelta(seconds=GOAL_READINESS_RECEIPT_MAX_AGE_SECONDS)
    ).replace(microsecond=0).isoformat()
    confirmation_reference = str(assessment.get("confirmationReference") or "")
    receipt = issue_receipt(
        {
            "kind": "goal-readiness",
            "schemaVersion": loop_core.GOAL_READINESS_RECEIPT_SCHEMA,
            "expiresAt": expires_at,
            "projectPath": subject_after["gitRoot"],
            "gitHead": subject_after["gitHead"],
            "projectFingerprint": subject_after["projectFingerprint"],
            "baseRef": subject_after.get("baseRef"),
            "baseCommit": subject_after.get("baseCommit"),
            "policyDigest": subject_after["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "loopId": loop_id,
            "priorContractDigest": prior_contract_digest,
            "readinessDigest": assessment["readinessDigest"],
            "contractInputDigest": assessment["contractInputDigest"],
            "contextDigest": assessment["contextDigest"],
            "confirmationRequired": assessment["confirmationRequired"],
            "confirmationReferenceDigest": (
                hashlib.sha256(confirmation_reference.encode("utf-8")).hexdigest()
                if confirmation_reference
                else None
            ),
            "passed": True,
        }
    )
    assessment["goalReadinessReceipt"] = receipt
    assessment["receiptExpiresAt"] = expires_at
    assessment["receiptIssued"] = True
    assessment["receiptMeaning"] = (
        "Session-local proof that the exact goal context and contract were readiness-checked "
        "against the current project state; it authorizes no implementation or external action."
    )
    return assessment


def tool_loop_start(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    subject, policy, worktree = stable_loop_contract_context(project_path)
    readiness_attestation = _verified_goal_readiness_attestation(
        args.get("goal_readiness_receipt"), subject
    )
    enriched_args = _loop_args_with_capabilities(args)
    service = _loop_service(project_path)
    result = _loop_call(
        lambda: service.start(
            enriched_args,
            subject=subject,
            worktree=worktree["isLinkedWorktree"],
            policy_source=policy.get("_sourcePath"),
            policy_digest=subject["policyDigest"],
            readiness_attestation=readiness_attestation,
        )
    )
    result["worktreeAttestation"] = worktree
    result["nativeGoalContract"] = {
        "createGoalRequired": True,
        "objective": result["goal"],
        "tokenBudget": args.get("token_budget"),
        "completionRule": "Call update_goal complete only after jstack_loop_finalize returns a current passed completionReceipt.",
        "blockedRule": "Call update_goal blocked only after the same blocker repeats for three consecutive Codex Goal turns.",
    }
    return result


def tool_loop_status(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    service = _loop_service(project_path)
    result = _loop_call(lambda: service.status(str(args.get("loop_id") or "") or None))
    subject = evidence_subject(project_path, result["baselineCommit"])
    result["projectState"] = {
        "gitHead": subject["gitHead"],
        "projectFingerprint": subject["projectFingerprint"],
        "clean": subject["clean"],
        "policyDigest": subject["policyDigest"],
        "toolVersion": subject["toolVersion"],
    }
    result["snapshotMatchesCurrentProject"] = (
        result.get("currentFingerprint") == subject["projectFingerprint"]
    )
    result["baselineAncestryValid"] = (
        subject.get("baseCommit") == result["baselineCommit"]
    )
    result["policyMatchesContract"] = result["policyDigest"] == subject["policyDigest"]
    result["toolVersionMatchesContract"] = (
        result["contractToolVersion"] == subject["toolVersion"]
    )
    result["capabilityCatalogMatchesContract"] = (
        _loop_capability_contract_matches(result)
    )
    return result


def tool_loop_checkpoint(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    service = _loop_service(project_path)
    loop_id = str(args.get("loop_id") or "")
    status = _loop_call(lambda: service.status(loop_id))
    context = _loop_iteration_evidence(project_path, status, args)
    return _loop_call(
        lambda: service.checkpoint(
            loop_id,
            expected_contract_digest=status["contractDigest"],
            subject=context["subject"],
            policy_digest=context["subject"]["policyDigest"],
            changed_files=context["changedFiles"],
            protected_files=context["protectedFiles"],
            evidence=context["evidence"],
            summary=str(args.get("iteration_summary") or ""),
            failure_signature=args.get("failure_signature"),
            blocker=args.get("blocker"),
        )
    )


def tool_loop_revise(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    subject, policy, worktree = stable_loop_contract_context(project_path)
    readiness_attestation = None
    if args.get("goal_readiness_receipt") is not None:
        readiness_attestation = _verified_goal_readiness_attestation(
            args.get("goal_readiness_receipt"), subject
        )
    service = _loop_service(project_path)
    loop_id = str(args.get("loop_id") or "")
    prior_status = _loop_call(lambda: service.status(loop_id))
    enriched_args = _loop_args_with_capabilities(args, prior_status)
    return _loop_call(
        lambda: service.revise(
            loop_id,
            enriched_args,
            subject=subject,
            worktree=worktree["isLinkedWorktree"],
            policy_source=policy.get("_sourcePath"),
            policy_digest=subject["policyDigest"],
            readiness_attestation=readiness_attestation,
        )
    )


def tool_loop_stop(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    service = _loop_service(project_path)
    return _loop_call(
        lambda: service.stop(
            str(args.get("loop_id") or ""),
            str(args.get("reason") or ""),
        )
    )


def tool_loop_finalize(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    service = _loop_service(project_path)
    loop_id = str(args.get("loop_id") or "")
    status = _loop_call(lambda: service.status(loop_id))
    context = _loop_iteration_evidence(project_path, status, args)
    result = _loop_call(
        lambda: service.finalize(
            loop_id,
            expected_contract_digest=status["contractDigest"],
            subject=context["subject"],
            policy_digest=context["subject"]["policyDigest"],
            changed_files=context["changedFiles"],
            protected_files=context["protectedFiles"],
            evidence=context["evidence"],
            summary=str(args.get("completion_summary") or ""),
        )
    )
    receipt_subject = evidence_subject(project_path, status["baselineCommit"])
    if any(
        receipt_subject[field] != context["subject"][field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed after loop finalization. No completion receipt was issued; restore the finalized state and revalidate it."
        )
    expires_at = (
        _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=RECEIPT_MAX_AGE_SECONDS)
    ).replace(microsecond=0).isoformat()
    receipt = issue_receipt(
        {
            "kind": "loop",
            "schemaVersion": "jstack.loop.receipt.v1",
            "expiresAt": expires_at,
            "projectPath": receipt_subject["gitRoot"],
            "gitHead": receipt_subject["gitHead"],
            "projectFingerprint": receipt_subject["projectFingerprint"],
            "baseRef": receipt_subject["baseRef"],
            "baseCommit": receipt_subject["baseCommit"],
            "policyDigest": receipt_subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "loopId": loop_id,
            "contractDigest": result["contractDigest"],
            "completionEvidenceDigest": result["completionEvidenceDigest"],
            "latestEventHash": result["latestEventHash"],
            "executionMode": result["executionMode"],
            "capabilityCatalogDigest": (result.get("capabilityContract") or {}).get(
                "catalogDigest"
            ),
            "capabilitySelectionDigest": (result.get("capabilityContract") or {}).get(
                "selectionDigest"
            ),
            "specialistHandoffReceiptDigest": (
                context["evidence"].get("specialistHandoff") or {}
            ).get("receiptDigest"),
            "autonomyLevel": result["autonomyLevel"],
            "riskTier": result["riskTier"],
            "passed": True,
        }
    )
    result["completionReceipt"] = receipt
    result["receiptMeaning"] = (
        "Session-local proof that the current Git state satisfied the versioned loop contract; "
        "it authorizes no repository, Git, release, deployment, production, or other blocked action."
    )
    return result


def _external_action_call(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return operation()
    except authorization_core.AuthorizationError as exc:
        raise ToolError(str(exc)) from exc


def _external_action_service(
    project_path: Path,
) -> authorization_core.AuthorizationService:
    try:
        return authorization_core.AuthorizationService(
            Path.home(), project_path, SERVER_SESSION_ID, _RECEIPT_SECRET
        )
    except authorization_core.AuthorizationError as exc:
        raise ToolError(str(exc)) from exc


def _external_action_identity_config() -> dict[str, dict[str, Any]]:
    configured = str(os.environ.get(EXTERNAL_ACTION_IDENTITY_CONFIG_ENV) or "").strip()
    if not configured:
        raise ToolError(
            "%s must point to a private signed-local identity configuration before an external action can be authorized."
            % EXTERNAL_ACTION_IDENTITY_CONFIG_ENV
        )
    path = Path(configured).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ToolError("External-action identity configuration is missing or unsafe.")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_000_000:
        raise ToolError(
            "External-action identity configuration must be a regular file no larger than 1 MB."
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolError("External-action identity configuration is malformed.") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "identities"}
        or value.get("schemaVersion") != EXTERNAL_ACTION_IDENTITY_CONFIG_SCHEMA
        or not isinstance(value.get("identities"), dict)
        or not 1 <= len(value["identities"]) <= 100
    ):
        raise ToolError("External-action identity configuration schema is invalid.")
    supported_roles = set(authorization_core.ACTION_ROLES.values())
    identities: dict[str, dict[str, Any]] = {}
    for identity_id, raw in value["identities"].items():
        if not isinstance(identity_id, str) or not re.fullmatch(
            r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", identity_id
        ):
            raise ToolError("External-action identity IDs must use lowercase hyphen-case.")
        if not isinstance(raw, dict) or set(raw) != {"roles", "hmacKeyEnv"}:
            raise ToolError("External-action identity records have unsupported fields.")
        roles = raw.get("roles")
        key_env = raw.get("hmacKeyEnv")
        if (
            not isinstance(roles, list)
            or not roles
            or len(roles) > len(supported_roles)
            or not all(isinstance(role, str) and role in supported_roles for role in roles)
            or len(set(roles)) != len(roles)
            or not isinstance(key_env, str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,100}", key_env)
        ):
            raise ToolError(
                "External-action identity roles or key environment binding is invalid."
            )
        key = str(os.environ.get(key_env) or "").encode("utf-8")
        if len(key) < 32:
            raise ToolError(
                "External-action identity %s requires at least 32 bytes in %s."
                % (identity_id, key_env)
            )
        identities[identity_id] = {
            "roles": sorted(roles),
            "key": key,
            "keyEnv": key_env,
        }
    return identities


def _external_action_git_context(project_path: Path) -> dict[str, Any]:
    branch_result = run_complete(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        project_path,
        timeout=10,
        max_bytes=100_000,
    )
    if not branch_result["ok"]:
        raise ToolError(
            "External-action authorization requires an attached exact branch; detached HEAD is ambiguous."
        )
    try:
        current_branch = branch_result["stdout"].decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ToolError("Current Git branch is not valid UTF-8.") from exc
    if not current_branch or "\n" in current_branch or "\r" in current_branch:
        raise ToolError("Current Git branch is missing or ambiguous.")
    remotes_result = run_complete(
        ["git", "remote"], project_path, timeout=10, max_bytes=100_000
    )
    if not remotes_result["ok"]:
        raise ToolError("Could not inspect Git remotes for external-action binding.")
    try:
        remote_names = [
            line.strip()
            for line in remotes_result["stdout"].decode("utf-8", errors="strict").splitlines()
            if line.strip()
        ]
    except UnicodeDecodeError as exc:
        raise ToolError("Git remote names are not valid UTF-8.") from exc
    if len(remote_names) > 100 or len(remote_names) != len(set(remote_names)):
        raise ToolError("Git remote inventory is too large or ambiguous.")
    remotes: list[dict[str, Any]] = []
    for name in sorted(remote_names):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            raise ToolError("Git contains a remote name that cannot be represented safely.")
        url_sets: dict[str, list[str]] = {}
        for label, extra in (("fetchUrls", []), ("pushUrls", ["--push"])):
            result = run_complete(
                ["git", "remote", "get-url", *extra, "--all", name],
                project_path,
                timeout=10,
                max_bytes=100_000,
            )
            if not result["ok"]:
                raise ToolError(f"Could not inspect Git remote '{name}' {label}.")
            try:
                urls = [
                    line.strip()
                    for line in result["stdout"].decode("utf-8", errors="strict").splitlines()
                    if line.strip()
                ]
            except UnicodeDecodeError as exc:
                raise ToolError("Git remote URL is not valid UTF-8.") from exc
            if not urls or len(urls) > 20 or any(len(url) > 1000 for url in urls):
                raise ToolError(
                    f"Git remote '{name}' has missing or ambiguous {label}."
                )
            url_sets[label] = urls
        remotes.append({"name": name, **url_sets})
    return {
        "currentBranch": current_branch,
        "remotes": remotes,
        "remoteSnapshotDigest": authorization_core.digest(remotes),
    }


def _external_action_binding(project_path: Path) -> dict[str, Any]:
    subject = evidence_subject(project_path)
    git_context = _external_action_git_context(project_path)
    return {
        "projectPath": subject["gitRoot"],
        "gitHead": subject["gitHead"],
        "projectFingerprint": subject["projectFingerprint"],
        "policyDigest": subject["policyDigest"],
        "toolVersion": SERVER_VERSION,
        "serverSession": SERVER_SESSION_ID,
        "currentBranch": git_context["currentBranch"],
        "remoteSnapshotDigest": git_context["remoteSnapshotDigest"],
    }


def _remote_url_identity(remote_url: str) -> dict[str, str]:
    scp_match = re.fullmatch(r"([^/@\s]+)@([^/:\s]+):(.+)", remote_url)
    if scp_match:
        username, host, raw_path = scp_match.groups()
        if username != "git":
            raise ToolError("SCP-style remote URLs must use the non-secret git username.")
    else:
        parsed = urllib.parse.urlsplit(remote_url)
        if (
            parsed.scheme not in {"https", "ssh"}
            or not parsed.hostname
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ToolError(
                "External remoteUrl must use HTTPS or SSH without credentials, query data, or fragments."
            )
        if parsed.username not in {None, "git"}:
            raise ToolError("External remoteUrl must not embed a user or access token.")
        host = parsed.hostname
        raw_path = parsed.path
    host = host.lower().rstrip(".")
    parts = [urllib.parse.unquote(part) for part in raw_path.strip("/").split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        raise ToolError("External remoteUrl does not contain an exact repository path.")
    if host == "dev.azure.com" and "_git" in parts:
        marker = parts.index("_git")
        if marker < 1 or marker + 1 != len(parts) - 1:
            raise ToolError("Azure DevOps remoteUrl does not contain an exact owner/repository path.")
        owner_parts = parts[:marker]
        repository = parts[-1]
    else:
        owner_parts = parts[:-1]
        repository = parts[-1]
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not owner_parts or not repository:
        raise ToolError("External remoteUrl does not contain an exact owner and repository.")
    if host == "github.com":
        provider = "github"
    elif host == "bitbucket.org":
        provider = "bitbucket"
    elif host == "dev.azure.com" or host.endswith(".visualstudio.com"):
        provider = "azure-devops"
    elif host == "gitlab.com" or "gitlab" in host:
        provider = "gitlab"
    else:
        provider = "other"
    return {
        "provider": provider,
        "owner": "/".join(owner_parts),
        "repository": repository,
    }


def _validated_external_action_target(
    project_path: Path,
    action: str,
    raw_target: Any,
) -> dict[str, Any]:
    try:
        target = authorization_core.normalize_target(raw_target, action)
    except authorization_core.AuthorizationError as exc:
        raise ToolError(str(exc)) from exc
    git_context = _external_action_git_context(project_path)
    commit = target["exactCommit"]
    commit_result = run_complete(
        ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
        project_path,
        timeout=10,
        max_bytes=10_000,
    )
    if not commit_result["ok"] or _git_text(commit_result).strip().lower() != commit:
        raise ToolError("target.exactCommit does not resolve to that exact local Git commit.")
    branch_result = run_complete(
        ["git", "check-ref-format", "--branch", target["branch"]],
        project_path,
        timeout=10,
        max_bytes=10_000,
    )
    if not branch_result["ok"]:
        raise ToolError("target.branch is not an exact valid Git branch name.")
    if action in {"commit", "repository_create", "remote_add", "remote_change"}:
        if commit != evidence_subject(project_path)["gitHead"]:
            raise ToolError(f"{action} must bind exactCommit to the current HEAD.")
    if action == "commit" and target["branch"] != git_context["currentBranch"]:
        raise ToolError("commit must bind target.branch to the current attached branch.")

    remote_map = {item["name"]: item for item in git_context["remotes"]}
    if target["provider"] == "local-git":
        if target["owner"] != "local" or target["repository"] != project_path.name:
            raise ToolError(
                "local-git actions require owner=local and repository equal to the project directory name."
            )
    else:
        identity = _remote_url_identity(target["remoteUrl"])
        if any(target[field] != identity[field] for field in ("provider", "owner", "repository")):
            raise ToolError(
                "target provider, owner, or repository does not match the exact remoteUrl."
            )
        remote_name = target["remoteName"]
        existing = remote_map.get(remote_name)
        if action in {"repository_create", "remote_add"}:
            if existing is not None or any(
                target["remoteUrl"] in item["fetchUrls"] + item["pushUrls"]
                for item in remote_map.values()
            ):
                raise ToolError(
                    f"{action} requires the exact remote name and URL to be absent locally."
                )
        elif action == "remote_change":
            if existing is None or len(existing["fetchUrls"]) != 1:
                raise ToolError(
                    "remote_change requires one unambiguous existing URL for the named remote."
                )
            if existing["fetchUrls"][0] == target["remoteUrl"]:
                raise ToolError("remote_change target already matches the existing remote URL.")
        elif action == "push":
            if existing is None or existing["pushUrls"] != [target["remoteUrl"]]:
                raise ToolError(
                    "push requires the named local remote to have exactly the authorized push URL."
                )
        elif action in {
            "pull_request_create",
            "merge",
            "release_create",
        }:
            if existing is None or existing["fetchUrls"] != [target["remoteUrl"]]:
                raise ToolError(
                    f"{action} requires the named local remote to have exactly the authorized URL."
                )
        elif existing is not None and (
            existing["fetchUrls"] != [target["remoteUrl"]]
            or existing["pushUrls"] != [target["remoteUrl"]]
        ):
            raise ToolError(
                "The named remote exists but does not exactly match the deployment/production target."
            )

    if action == "push":
        if target["tag"] == authorization_core.NOT_APPLICABLE:
            push_ref = f"refs/heads/{target['branch']}"
            push_ref_kind = "branch"
        else:
            push_ref = f"refs/tags/{target['tag']}"
            push_ref_kind = "tag"
        push_ref_result = run_complete(
            ["git", "rev-parse", "--verify", f"{push_ref}^{{commit}}"],
            project_path,
            timeout=10,
            max_bytes=10_000,
        )
        if (
            not push_ref_result["ok"]
            or _git_text(push_ref_result).strip().lower() != commit
        ):
            raise ToolError(
                f"push requires the exact local {push_ref_kind} to resolve to exactCommit."
            )

    if action in {"tag_create", "release_create"}:
        tag_ref = f"refs/tags/{target['tag']}"
        tag_result = run_complete(
            ["git", "rev-parse", "--verify", f"{tag_ref}^{{commit}}"],
            project_path,
            timeout=10,
            max_bytes=10_000,
        )
        if action == "tag_create" and tag_result["ok"]:
            raise ToolError("tag_create requires the exact tag to be absent.")
        if action == "release_create" and (
            not tag_result["ok"] or _git_text(tag_result).strip().lower() != commit
        ):
            raise ToolError(
                "release_create requires the exact local tag to resolve to exactCommit."
            )
    return target


def _verify_external_action_attestation(
    token: str,
    authorization_id: str,
    max_seconds: int,
) -> dict[str, Any]:
    if (
        not isinstance(token, str)
        or not token
        or len(token) > EXTERNAL_ACTION_MAX_RECEIPT_CHARS
    ):
        raise ToolError("approval_attestation must be one bounded signed token.")
    try:
        encoded, supplied_signature = token.split(".", 1)
        raw = _b64decode(encoded)
        payload = json.loads(raw.decode("utf-8"))
        normalized = authorization_core.validate_attestation_payload(
            payload, max_seconds=max_seconds
        )
        if raw != authorization_core.canonical(normalized):
            raise ValueError("non-canonical payload")
        identity = _external_action_identity_config()[normalized["approverId"]]
        expected_signature = _b64encode(
            hmac.new(identity["key"], encoded.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("signature")
    except Exception as exc:
        raise ToolError(
            "External-action attestation is malformed, unsigned, expired, non-canonical, or not issued by a configured identity."
        ) from exc
    if normalized["authorizationId"] != authorization_id:
        raise ToolError("External-action attestation belongs to a different authorization ID.")
    if normalized["requiredRole"] not in identity["roles"]:
        raise ToolError("Configured identity lacks the exact role required for this action.")
    return {
        **normalized,
        "identityRoles": identity["roles"],
        "attestationDigest": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }


def tool_external_action_challenge(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    action = str(args.get("action") or "")
    approver_id = str(args.get("approver_id") or "").strip()
    approval_reference = str(args.get("approval_reference") or "").strip()
    if not approval_reference or len(approval_reference) > 500:
        raise ToolError("A bounded external approval reference is required.")
    if audit_core.contains_secret_like(approval_reference):
        raise ToolError("Approval references must not contain secret-like values.")
    identities = _external_action_identity_config()
    identity = identities.get(approver_id)
    if identity is None:
        raise ToolError("Unknown or disabled signed-local external-action identity.")
    required_role = authorization_core.ACTION_ROLES.get(action)
    if required_role is None or required_role not in identity["roles"]:
        raise ToolError("The selected identity does not hold the exact role required by this action.")
    target = _validated_external_action_target(project_path, action, args.get("target"))
    policy = load_enterprise_policy(project_path)
    external_policy = policy["externalActions"]
    requested_seconds = int(
        args.get("valid_for_seconds")
        or external_policy["maxAuthorizationSeconds"]
    )
    maximum_seconds = int(external_policy["maxAuthorizationSeconds"])
    issued = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    authorization_id = (
        "authorization-"
        + issued.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + secrets.token_hex(6)
    )
    binding = _external_action_binding(project_path)
    try:
        payload = authorization_core.create_attestation_payload(
            authorization_id=authorization_id,
            action=action,
            target=target,
            binding=binding,
            approver_id=approver_id,
            approval_reference_digest=hashlib.sha256(
                approval_reference.encode("utf-8")
            ).hexdigest(),
            nonce=secrets.token_hex(16),
            valid_for_seconds=requested_seconds,
            issued_at=issued,
            max_seconds=maximum_seconds,
        )
    except authorization_core.AuthorizationError as exc:
        raise ToolError(str(exc)) from exc
    challenge = _external_action_call(
        lambda: _external_action_service(project_path).create_challenge(payload)
    )
    encoded = _b64encode(authorization_core.canonical(payload))
    return {
        "schemaVersion": authorization_core.CHALLENGE_SCHEMA,
        "authorizationId": authorization_id,
        "challenge": payload,
        "challengeDigest": challenge["challengeDigest"],
        "encodedPayload": encoded,
        "signatureAlgorithm": "HMAC-SHA256",
        "keyEnvironment": identity["keyEnv"],
        "confirmationText": (
            "AUTHORIZE JSTACK EXTERNAL ACTION "
            + challenge["challengeDigest"]
            + " ONCE"
        ),
        "signingRule": (
            "The named human reviews every field and signs encodedPayload outside Codex with the private key in keyEnvironment and the full challengeDigest. Codex must not run the signer or create the approval."
        ),
        "authorityRule": (
            "This challenge authorizes nothing. Implement, build, finish, ship, deploy, release, phase approval, remediation approval, and loop/program completion are never substitutes for this exact signed action."
        ),
    }


def tool_external_action_authorize(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    authorization_id = str(args.get("authorization_id") or "")
    policy = load_enterprise_policy(project_path)
    external_policy = policy["externalActions"]
    attestation = _verify_external_action_attestation(
        str(args.get("approval_attestation") or ""),
        authorization_id,
        int(external_policy["maxAuthorizationSeconds"]),
    )
    action = attestation["actionSet"][0]
    _validated_external_action_target(project_path, action, attestation["target"])
    current_binding = _external_action_binding(project_path)
    grant = _external_action_call(
        lambda: _external_action_service(project_path).authorize(
            authorization_id,
            {
                key: value
                for key, value in attestation.items()
                if key not in {"identityRoles", "attestationDigest"}
            },
            attestation_digest=attestation["attestationDigest"],
            current_binding=current_binding,
        )
    )
    subject = evidence_subject(project_path)
    receipt = issue_receipt(
        {
            "kind": "external-action-authorization",
            "schemaVersion": "jstack.external-action.authorization-receipt.v1",
            "expiresAt": attestation["expiresAt"],
            "projectPath": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "baseRef": subject.get("baseRef"),
            "baseCommit": subject.get("baseCommit"),
            "policyDigest": subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "authorizationId": authorization_id,
            "actionSet": attestation["actionSet"],
            "requiredRole": attestation["requiredRole"],
            "target": attestation["target"],
            "bindingDigest": authorization_core.digest(attestation["binding"]),
            "challengeDigest": grant["challengeDigest"],
            "attestationDigest": attestation["attestationDigest"],
            "approverId": attestation["approverId"],
            "approvalReferenceDigest": attestation["approvalReferenceDigest"],
            "passed": True,
        }
    )
    return {
        "schemaVersion": authorization_core.GRANT_SCHEMA,
        "authorized": True,
        "authorizationId": authorization_id,
        "action": action,
        "target": attestation["target"],
        "expiresAt": attestation["expiresAt"],
        "authorizationReceipt": receipt,
        "receiptMeaning": (
            "A short-lived session/Git/remote/target-bound approval awaiting one destructive consumption. It is not an execution result and cannot authorize any other action."
        ),
    }


def tool_external_action_consume(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    receipt = str(args.get("authorization_receipt") or "")
    if not receipt or len(receipt) > EXTERNAL_ACTION_MAX_RECEIPT_CHARS:
        raise ToolError("A bounded authorization_receipt is required.")
    action = str(args.get("action") or "")
    operation_id = str(args.get("operation_id") or "")
    subject = evidence_subject(project_path)
    verification = verify_receipt(
        receipt,
        "external-action-authorization",
        subject,
        expected_subject=subject,
    )
    payload = verification["payload"]
    if (
        not verification["valid"]
        or payload.get("schemaVersion")
        != "jstack.external-action.authorization-receipt.v1"
        or payload.get("actionSet") != [action]
    ):
        raise ToolError(
            "Authorization receipt is stale, mismatched, escalated, or bound to another project state/action."
        )
    target = _validated_external_action_target(
        project_path, action, payload.get("target")
    )
    current_binding = _external_action_binding(project_path)
    if authorization_core.digest(current_binding) != payload.get("bindingDigest"):
        raise ToolError(
            "Git branch or remote state drifted after authorization; obtain a fresh exact approval."
        )
    observation = args.get("observation")
    if isinstance(observation, dict) and audit_core.contains_secret_like(
        str(observation.get("source") or "")
    ):
        raise ToolError("Provider observation references must not contain secret-like values.")
    receipt_digest = hashlib.sha256(receipt.encode("utf-8")).hexdigest()
    consumption = _external_action_call(
        lambda: _external_action_service(project_path).consume(
            str(payload.get("authorizationId") or ""),
            action=action,
            operation_id=operation_id,
            authorization_receipt_digest=receipt_digest,
            observation=observation,
            current_binding=current_binding,
        )
    )
    policy = load_enterprise_policy(project_path)["externalActions"]
    now_utc = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    authorization_expiry = _dt.datetime.fromisoformat(str(payload["expiresAt"]))
    permit_expiry = min(
        authorization_expiry,
        now_utc
        + _dt.timedelta(seconds=int(policy["permitMaxAgeSeconds"])),
    )
    if permit_expiry <= now_utc:
        raise ToolError("Authorization expired before an execution permit could be issued.")
    permit = issue_receipt(
        {
            "kind": "external-action-permit",
            "schemaVersion": "jstack.external-action.permit.v1",
            "expiresAt": permit_expiry.isoformat(),
            "projectPath": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "baseRef": subject.get("baseRef"),
            "baseCommit": subject.get("baseCommit"),
            "policyDigest": subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "authorizationId": payload["authorizationId"],
            "operationId": operation_id,
            "action": action,
            "target": target,
            "consumptionDigest": authorization_core.digest(consumption),
            "passed": True,
        }
    )
    return {
        "schemaVersion": authorization_core.CONSUMPTION_SCHEMA,
        "authorized": True,
        "consumed": True,
        "authorizationId": payload["authorizationId"],
        "operationId": operation_id,
        "action": action,
        "target": target,
        "permitExpiresAt": permit_expiry.isoformat(),
        "executionPermit": permit,
        "executionRule": (
            "Execute this one exact action at most once before permit expiry. Do not retry, widen, substitute, or continue to another action; failure or any drift requires a new signed challenge."
        ),
    }


def _program_service(project_path: Path) -> program_core.ProgramService:
    return program_core.ProgramService(Path.home(), project_path)


def _program_operation_id(args: dict[str, Any]) -> str:
    value = args.get("operation_id")
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", value
    ):
        raise ToolError(
            "A unique operation_id using 1-100 letters, numbers, dots, underscores, colons, or hyphens is required."
        )
    return value


def _program_call(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return operation()
    except program_core.ProgramError as exc:
        raise ToolError(str(exc)) from exc


def _program_policy_gaps(args: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, str]]:
    criteria = args.get("final_acceptance_criteria") or []
    verifiers = [
        item.get("verifier") or {}
        for item in criteria
        if isinstance(item, dict)
    ]
    gaps: list[dict[str, str]] = []
    program_policy = policy.get("program") or {}
    if program_policy.get("requireFinalAudit") is True and not any(
        verifier.get("type") == "audit" and verifier.get("profile") == "release"
        for verifier in verifiers
    ):
        gaps.append(
            {
                "id": "final-release-audit",
                "question": "Add a final audit criterion using the release profile so program completion has complete current audit coverage.",
            }
        )
    if program_policy.get("requireCurrentEvidence") is True and not any(
        verifier.get("type") == "security" for verifier in verifiers
    ):
        gaps.append(
            {
                "id": "final-security",
                "question": "Add a final security criterion backed by a current JStack security receipt.",
            }
        )
    if program_policy.get("requireCurrentEvidence") is True and not any(
        verifier.get("type") == "review" for verifier in verifiers
    ):
        gaps.append(
            {
                "id": "final-review",
                "question": "Add a final deterministic review criterion for the complete integrated program delta.",
            }
        )
    return gaps


def _verified_program_readiness_attestation(
    receipt: Any, subject: dict[str, Any]
) -> dict[str, Any]:
    if (
        not isinstance(receipt, str)
        or not receipt
        or len(receipt) > PROGRAM_MAX_RECEIPT_CHARS
    ):
        raise ToolError(
            "A bounded program_readiness_receipt returned by jstack_program_goal_readiness is required."
        )
    verification = verify_receipt(
        receipt,
        "program-goal-readiness",
        subject,
        expected_subject=subject,
    )
    payload = verification["payload"]
    if (
        not verification["valid"]
        or payload.get("schemaVersion")
        != program_core.PROGRAM_READINESS_RECEIPT_SCHEMA
    ):
        raise ToolError(
            "The program-readiness receipt is stale, malformed, from another session, or bound to a different project state."
        )
    return {**payload, "receiptDigest": _receipt_digest(receipt)}


def _program_baseline_ancestry(project_path: Path, baseline: str) -> bool:
    result = run_complete(
        ["git", "merge-base", baseline, "HEAD"],
        project_path,
        timeout=10,
    )
    return result["ok"] and _git_text(result).strip() == baseline


def _program_identity_config() -> dict[str, dict[str, Any]]:
    configured = str(os.environ.get(PROGRAM_IDENTITY_CONFIG_ENV) or "").strip()
    if not configured:
        raise ToolError(
            "%s must point to a private signed-local identity configuration before human program gates can be resolved."
            % PROGRAM_IDENTITY_CONFIG_ENV
        )
    path = Path(configured).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ToolError("Program identity configuration is missing or unsafe.")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_000_000:
        raise ToolError("Program identity configuration must be a regular file no larger than 1 MB.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolError("Program identity configuration is malformed.") from exc
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != PROGRAM_IDENTITY_CONFIG_SCHEMA
        or not isinstance(value.get("identities"), dict)
        or not 1 <= len(value["identities"]) <= 100
    ):
        raise ToolError("Program identity configuration schema is invalid.")
    result: dict[str, dict[str, Any]] = {}
    for identity, raw in value["identities"].items():
        if not isinstance(identity, str) or not re.fullmatch(
            r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", identity
        ):
            raise ToolError("Program identity IDs must use lowercase hyphen-case.")
        if not isinstance(raw, dict):
            raise ToolError("Program identity records must be objects.")
        roles = raw.get("roles")
        key_env = raw.get("hmacKeyEnv")
        if (
            not isinstance(roles, list)
            or not roles
            or len(roles) > 20
            or not all(
                isinstance(role, str)
                and re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", role)
                for role in roles
            )
            or not isinstance(key_env, str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,100}", key_env)
        ):
            raise ToolError("Program identity roles or key environment binding is invalid.")
        key = str(os.environ.get(key_env) or "").encode("utf-8")
        if len(key) < 32:
            raise ToolError(
                "Program identity %s requires at least 32 bytes in %s."
                % (identity, key_env)
            )
        result[identity] = {
            "roles": sorted(set(roles)),
            "key": key,
            "keyEnv": key_env,
        }
    return result


def _program_gate_challenge(
    project_path: Path,
    program_id: str,
    gate_id: str,
    approver_id: str,
    decision: str,
    reference: str,
    valid_for_minutes: Optional[int],
) -> dict[str, Any]:
    service = _program_service(project_path)
    context = _program_call(lambda: service.gate_context(program_id, gate_id))
    gate = context["gate"]
    if gate["type"] != "human":
        raise ToolError("Only human program gates use signed approval challenges.")
    identities = _program_identity_config()
    identity = identities.get(approver_id)
    if identity is None:
        raise ToolError("Unknown or disabled signed-local program identity.")
    if not set(identity["roles"]) & set(gate["requiredRoles"]):
        raise ToolError("The selected identity does not hold a role required by this gate.")
    if decision not in {"approved", "rejected"}:
        raise ToolError("Program gate decision must be approved or rejected.")
    reference = str(reference or "").strip()
    if not reference or len(reference) > 500:
        raise ToolError("A bounded external approval reference is required.")
    if audit_core.contains_secret_like(reference):
        raise ToolError("Approval references must not contain secret-like values.")
    requested = int(valid_for_minutes or min(60, int(gate["maxAgeMinutes"])))
    if not 1 <= requested <= int(gate["maxAgeMinutes"]):
        raise ToolError(
            "valid_for_minutes must be within the gate maximum of %d."
            % gate["maxAgeMinutes"]
        )
    issued = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    expires = issued + _dt.timedelta(minutes=requested)
    payload = {
        "schemaVersion": program_core.APPROVAL_ATTESTATION_SCHEMA,
        "programId": program_id,
        "gateId": gate_id,
        "contractDigest": context["contractDigest"],
        "gateDigest": context["gateDigest"],
        "approverId": approver_id,
        "decision": decision,
        "referenceDigest": hashlib.sha256(reference.encode("utf-8")).hexdigest(),
        "issuedAt": issued.isoformat(),
        "expiresAt": expires.isoformat(),
        "nonce": secrets.token_hex(16),
    }
    encoded = _b64encode(_canonical_program_payload(payload))
    return {
        "schemaVersion": "jstack.program.approval-challenge.v1",
        "challenge": payload,
        "encodedPayload": encoded,
        "signatureAlgorithm": "HMAC-SHA256",
        "keyEnvironment": identity["keyEnv"],
        "requiredRoles": gate["requiredRoles"],
        "identityRoles": identity["roles"],
        "signingRule": (
            "The named human approver signs encodedPayload with the private key in keyEnvironment; "
            "Codex must not create or claim the approval."
        ),
    }


def _canonical_program_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _verify_program_approval_token(
    token: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > PROGRAM_MAX_RECEIPT_CHARS:
        raise ToolError("approval_attestation must be a bounded signed token.")
    try:
        encoded, supplied_signature = token.split(".", 1)
        payload = json.loads(_b64decode(encoded).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("payload")
        approver_id = str(payload.get("approverId") or "")
        identities = _program_identity_config()
        identity = identities[approver_id]
        expected_signature = _b64encode(
            hmac.new(identity["key"], encoded.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("signature")
        issued = _dt.datetime.fromisoformat(str(payload["issuedAt"]))
        expires = _dt.datetime.fromisoformat(str(payload["expiresAt"]))
        if issued.tzinfo is None or expires.tzinfo is None:
            raise ValueError("timezone")
    except Exception as exc:
        raise ToolError(
            "Program approval attestation is malformed, unsigned, expired, or not issued by a configured identity."
        ) from exc
    gate = context["gate"]
    now = _dt.datetime.now(_dt.timezone.utc)
    checks = {
        "schema": payload.get("schemaVersion")
        == program_core.APPROVAL_ATTESTATION_SCHEMA,
        "program": payload.get("programId") == context["programId"],
        "gate": payload.get("gateId") == gate["id"],
        "contract": payload.get("contractDigest") == context["contractDigest"],
        "gateDigest": payload.get("gateDigest") == context["gateDigest"],
        "decision": payload.get("decision") in {"approved", "rejected"},
        "reference": isinstance(payload.get("referenceDigest"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", payload["referenceDigest"])),
        "nonce": isinstance(payload.get("nonce"), str)
        and bool(re.fullmatch(r"[0-9a-f]{32}", payload["nonce"])),
        "fresh": issued <= now < expires,
        "bounded": 0
        < (expires - issued).total_seconds()
        <= int(gate["maxAgeMinutes"]) * 60,
        "role": bool(set(identity["roles"]) & set(gate["requiredRoles"])),
    }
    if not all(checks.values()):
        raise ToolError("Program approval attestation does not match the current gate contract.")
    return {
        **payload,
        "roles": identity["roles"],
        "attestationDigest": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }


def _program_artifact_path(
    project_path: Path, raw_path: str
) -> tuple[Path, str, Path]:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = project_path / candidate
    if candidate.is_symlink():
        raise ToolError("Program evidence artifacts may not be symlinks.")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ToolError("Program evidence artifact is missing or inaccessible.") from exc
    allowed_roots = [
        project_path.resolve(),
        (Path.home() / ".jstack" / "evidence").resolve(strict=False),
    ]
    selected_root = None
    relative = None
    for root in allowed_roots:
        try:
            candidate_relative = resolved.relative_to(root)
        except ValueError:
            continue
        if candidate_relative.parts:
            selected_root = root
            relative = candidate_relative.as_posix()
            break
    if selected_root is None or relative is None:
        raise ToolError(
            "External evidence must be inside the Git project or ~/.jstack/evidence."
        )
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > PROGRAM_MAX_ARTIFACT_BYTES:
        raise ToolError("Program evidence must be a regular file no larger than 100 MB.")
    return selected_root, relative, resolved


def _program_file_digest(
    root: Path,
    relative_path: str,
    *,
    maximum: int,
) -> tuple[int, str]:
    try:
        return audit_core.digest_repository_file(
            root,
            relative_path,
            max_bytes=maximum,
            max_seconds=PROGRAM_ARTIFACT_TIMEOUT_SECONDS,
        )
    except audit_core.AuditError as exc:
        raise ToolError(
            "Program evidence artifact could not be opened with stable file identity."
        ) from exc


def _program_phase_output_digests(
    child_project: Path,
    outputs: list[dict[str, Any]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    total = 0
    for output in outputs:
        remaining = PROGRAM_MAX_ARTIFACT_BYTES - total
        if remaining <= 0:
            raise ToolError("Program phase outputs exceed the aggregate 100 MB boundary.")
        try:
            size, digest = audit_core.digest_repository_file(
                child_project,
                output["path"],
                max_bytes=min(25_000_000, remaining),
                max_seconds=PROGRAM_ARTIFACT_TIMEOUT_SECONDS,
            )
        except audit_core.AuditError as exc:
            raise ToolError(
                "Program phase output is missing or unsafe: %s" % output["path"]
            ) from exc
        total += size
        result[output["id"]] = digest
    return result


def _program_child_integrity(
    status: dict[str, Any],
    *,
    verify_outputs: bool,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for phase in status.get("phases", []):
        proof = phase.get("completionProof")
        child = phase.get("child")
        if not isinstance(proof, dict):
            continue
        checks: dict[str, bool] = {}
        error = None
        try:
            if not isinstance(child, dict):
                raise ToolError("missing child binding")
            child_project = require_project_path(child.get("projectPath"))
            worktree = git_worktree_attestation(child_project)
            attestation = _loop_call(
                lambda: _loop_service(child_project).completion_attestation(
                    str(child.get("loopId") or "")
                )
            )
            checks = {
                "commonRepository": worktree["commonDirDigest"]
                == status["commonDirDigest"],
                "loopId": attestation.get("loopId") == proof.get("loopId"),
                "projectPath": attestation.get("projectPath")
                == proof.get("projectPath"),
                "contractDigest": attestation.get("contractDigest")
                == proof.get("contractDigest"),
                "completionEvidence": attestation.get("completionEvidenceDigest")
                == proof.get("loopCompletionEvidenceDigest"),
                "eventHead": attestation.get("latestEventHash")
                == proof.get("loopLatestEventHash"),
                "passed": attestation.get("passed") is True,
            }
            if verify_outputs:
                current_outputs = _program_phase_output_digests(
                    child_project, phase.get("outputs") or []
                )
                checks["outputs"] = current_outputs == phase.get("outputDigests", {})
        except (ToolError, OSError) as exc:
            error = str(exc)
            checks["load"] = False
        results.append(
            {
                "phaseId": phase["id"],
                "valid": bool(checks) and all(checks.values()),
                "checks": checks,
                "error": error,
            }
        )
    return {
        "valid": all(item["valid"] for item in results),
        "phases": results,
        "outputsVerified": verify_outputs,
    }


def _program_status_integrity(
    project_path: Path,
    status: dict[str, Any],
    *,
    verify_outputs: bool = False,
) -> dict[str, Any]:
    subject = evidence_subject(project_path)
    worktree = git_worktree_attestation(project_path)
    child_integrity = _program_child_integrity(
        status, verify_outputs=verify_outputs
    )
    context_checks = {
        "policy": status["policyDigest"] == subject["policyDigest"],
        "toolVersion": status["contractToolVersion"] == subject["toolVersion"],
        "commonRepository": status["commonDirDigest"]
        == worktree["commonDirDigest"],
        "baselineAncestry": _program_baseline_ancestry(
            project_path, status["baselineCommit"]
        ),
    }
    passed = all(context_checks.values()) and child_integrity["valid"]
    status["integrity"] = {
        "valid": passed,
        "contextChecks": context_checks,
        "childProofs": child_integrity,
        "currentProject": {
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "policyDigest": subject["policyDigest"],
            "toolVersion": subject["toolVersion"],
        },
    }
    if not passed and status["status"] not in {"completed", "cancelled"}:
        status["status"] = "blocked"
        status["decision"] = "needs_revision"
        status["readyPhaseIds"] = []
    status["completionRevalidatable"] = passed
    return status


def tool_program_goal_readiness(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    subject, policy, worktree = stable_loop_contract_context(project_path)
    policy_gaps = _program_policy_gaps(args, policy)
    if policy_gaps:
        return {
            "schemaVersion": program_core.PROGRAM_READINESS_SCHEMA,
            "status": "needs_context",
            "ready": False,
            "gaps": [item["id"] for item in policy_gaps],
            "questions": [
                {"id": item["id"], "question": item["question"], "blocking": True}
                for item in policy_gaps[:3]
            ],
            "receiptIssued": False,
        }
    service = _program_service(project_path)
    program_id = str(args.get("program_id") or "").strip() or None
    prior_contract_digest = None
    if program_id:
        status = _program_call(lambda: service.status(program_id))
        if status["status"] in {"completed", "cancelled"}:
            raise ToolError("Terminal programs cannot receive a revised readiness receipt.")
        prior_contract_digest = status["contractDigest"]
    assessment = _program_call(
        lambda: program_core.assess_program_readiness(
            args,
            project_root=str(project_path),
            subject=subject,
            policy_source=policy.get("_sourcePath"),
            policy_digest=subject["policyDigest"],
            common_dir_digest=worktree["commonDirDigest"],
            program_policy=policy.get("program"),
            program_id=program_id,
            prior_contract_digest=prior_contract_digest,
        )
    )
    assessment.pop("_contract", None)
    if assessment.get("ready") is not True:
        assessment["receiptIssued"] = False
        return assessment
    subject_after = evidence_subject(project_path)
    if any(
        subject_after[field] != subject[field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed during program-readiness assessment. Re-run against one stable state."
        )
    expires_at = (
        _dt.datetime.now(_dt.timezone.utc)
        + _dt.timedelta(seconds=GOAL_READINESS_RECEIPT_MAX_AGE_SECONDS)
    ).replace(microsecond=0).isoformat()
    confirmation_reference = str(assessment.get("confirmationReference") or "")
    receipt = issue_receipt(
        {
            "kind": "program-goal-readiness",
            "schemaVersion": program_core.PROGRAM_READINESS_RECEIPT_SCHEMA,
            "expiresAt": expires_at,
            "projectPath": subject_after["gitRoot"],
            "gitHead": subject_after["gitHead"],
            "projectFingerprint": subject_after["projectFingerprint"],
            "baseRef": subject_after.get("baseRef"),
            "baseCommit": subject_after.get("baseCommit"),
            "policyDigest": subject_after["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "programId": program_id,
            "priorContractDigest": prior_contract_digest,
            "readinessDigest": assessment["readinessDigest"],
            "contractInputDigest": assessment["contractInputDigest"],
            "confirmationRequired": assessment["confirmationRequired"],
            "confirmationReferenceDigest": (
                hashlib.sha256(confirmation_reference.encode("utf-8")).hexdigest()
                if confirmation_reference
                else None
            ),
            "passed": True,
        }
    )
    assessment.update(
        {
            "programReadinessReceipt": receipt,
            "receiptExpiresAt": expires_at,
            "receiptIssued": True,
            "receiptMeaning": (
                "Session-local proof that the exact program DAG and acceptance boundary were readiness-checked; "
                "it does not approve implementation, release, deployment, or a human gate."
            ),
        }
    )
    return assessment


def tool_program_start(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    subject, policy, worktree = stable_loop_contract_context(project_path)
    if subject.get("clean") is not True:
        raise ToolError("Program orchestration must start from a clean Git worktree.")
    policy_gaps = _program_policy_gaps(args, policy)
    if policy_gaps:
        raise ToolError(
            "Program contract does not satisfy policy: "
            + ", ".join(item["id"] for item in policy_gaps)
        )
    attestation = _verified_program_readiness_attestation(
        args.get("program_readiness_receipt"), subject
    )
    service = _program_service(project_path)
    result = _program_call(
        lambda: service.start(
            args,
            subject=subject,
            policy_source=policy.get("_sourcePath"),
            policy_digest=subject["policyDigest"],
            common_dir_digest=worktree["commonDirDigest"],
            program_policy=policy.get("program"),
            readiness_attestation=attestation,
            operation_id=operation_id,
        )
    )
    result = _program_status_integrity(project_path, result)
    result["nativeGoalContract"] = {
        "createGoalRequired": True,
        "objective": result["goal"],
        "completionRule": (
            "Complete the native goal only after jstack_program_finalize returns a current passed completionReceipt."
        ),
        "blockedRule": (
            "Human or external waiting states are durable pauses, not native Goal blocked status."
        ),
    }
    return result


def tool_program_status(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    service = _program_service(project_path)
    result = _program_call(
        lambda: service.status(str(args.get("program_id") or "") or None)
    )
    return _program_status_integrity(project_path, result)


def tool_program_next(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    service = _program_service(project_path)
    result = _program_call(
        lambda: service.next(str(args.get("program_id") or ""))
    )
    result = _program_status_integrity(project_path, result)
    if result["status"] != "running":
        result["scheduledPhaseIds"] = []
    return result


def tool_program_phase_bind(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    child_project = require_project_path(
        args.get("child_project_path") or args.get("project_path")
    )
    program_id = str(args.get("program_id") or "")
    phase_id = str(args.get("phase_id") or "")
    loop_id = str(args.get("loop_id") or "")
    parent_status = tool_program_status(
        {"project_path": str(project_path), "program_id": program_id}
    )
    if parent_status["status"] != "running":
        raise ToolError("Program integrity or lifecycle state does not allow phase binding.")
    child_status = _loop_call(lambda: _loop_service(child_project).status(loop_id))
    if child_status["status"] != "active":
        raise ToolError("Only an active bounded child loop can be bound to a program phase.")
    worktree = git_worktree_attestation(child_project)
    child = {
        "loopId": loop_id,
        "projectPath": str(child_project),
        "contractDigest": child_status["contractDigest"],
        "baselineCommit": child_status["baselineCommit"],
        "commonDirDigest": worktree["commonDirDigest"],
        "isLinkedWorktree": worktree["isLinkedWorktree"],
        "goal": child_status["goal"],
        "executionMode": child_status["executionMode"],
        "autonomyLevel": child_status["autonomyLevel"],
        "riskTier": child_status["riskTier"],
        "allowedPaths": child_status["allowedPaths"],
        "blockedActions": child_status["blockedActions"],
        "acceptanceCriteria": child_status["acceptanceCriteria"],
    }
    result = _program_call(
        lambda: _program_service(project_path).bind_phase(
            program_id, phase_id, child, operation_id=operation_id
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_phase_complete(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    phase_id = str(args.get("phase_id") or "")
    status = _program_call(lambda: _program_service(project_path).status(program_id))
    phase = next((item for item in status["phases"] if item["id"] == phase_id), None)
    if phase is None or not isinstance(phase.get("child"), dict):
        raise ToolError("Program phase has no bound child loop.")
    child = phase["child"]
    child_project = require_project_path(child["projectPath"])
    subject = evidence_subject(child_project, child["baselineCommit"])
    receipt = args.get("loop_completion_receipt")
    if not isinstance(receipt, str) or len(receipt) > PROGRAM_MAX_RECEIPT_CHARS:
        raise ToolError("A bounded current child loop completion receipt is required.")
    verification = verify_receipt(
        receipt,
        "loop",
        subject,
        expected_subject=subject,
    )
    durable = _loop_call(
        lambda: _loop_service(child_project).completion_attestation(child["loopId"])
    )
    payload = verification["payload"]
    if (
        not verification["valid"]
        or payload.get("loopId") != child["loopId"]
        or payload.get("contractDigest") != child["contractDigest"]
        or payload.get("completionEvidenceDigest")
        != durable["completionEvidenceDigest"]
        or payload.get("latestEventHash") != durable["latestEventHash"]
    ):
        raise ToolError("Child loop completion receipt and durable loop state do not match.")
    output_digests = _program_phase_output_digests(
        child_project, phase.get("outputs") or []
    )
    proof = {
        "schemaVersion": program_core.PHASE_COMPLETION_PROOF_SCHEMA,
        "programId": program_id,
        "phaseId": phase_id,
        "phaseDigest": phase["phaseDigest"],
        "loopId": child["loopId"],
        "projectPath": str(child_project),
        "contractDigest": child["contractDigest"],
        "loopCompletionEvidenceDigest": durable["completionEvidenceDigest"],
        "loopLatestEventHash": durable["latestEventHash"],
        "loopReceiptDigest": _receipt_digest(receipt),
        "completedAt": durable["completedAt"],
        "passed": True,
    }
    result = _program_call(
        lambda: _program_service(project_path).complete_phase(
            program_id,
            phase_id,
            proof,
            output_digests,
            operation_id=operation_id,
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_gate_challenge(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    project_path = require_project_path(args.get("project_path"))
    return _program_gate_challenge(
        project_path,
        str(args.get("program_id") or ""),
        str(args.get("gate_id") or ""),
        str(args.get("approver_id") or ""),
        str(args.get("decision") or ""),
        str(args.get("approval_reference") or ""),
        args.get("valid_for_minutes"),
    )


def tool_program_gate_resolve(args: dict[str, Any]) -> dict[str, Any]:
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    gate_id = str(args.get("gate_id") or "")
    service = _program_service(project_path)
    context = _program_call(lambda: service.gate_context(program_id, gate_id))
    approval = _verify_program_approval_token(
        str(args.get("approval_attestation") or ""), context
    )
    result = _program_call(
        lambda: service.resolve_gate(
            program_id, gate_id, approval, operation_id=operation_id
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_evidence_register(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    gate_id = str(args.get("gate_id") or "")
    source_reference = str(args.get("source_reference") or "").strip()
    if not source_reference or len(source_reference) > 500:
        raise ToolError("A bounded source_reference is required.")
    if audit_core.contains_secret_like(source_reference):
        raise ToolError("External evidence references must not contain secret-like values.")
    service = _program_service(project_path)
    context = _program_call(lambda: service.gate_context(program_id, gate_id))
    gate = context["gate"]
    if gate["type"] != "external":
        raise ToolError("Human gates require signed identity attestations.")
    artifact_root, artifact_relative, artifact = _program_artifact_path(
        project_path, str(args.get("artifact_path") or "")
    )
    size, digest = _program_file_digest(
        artifact_root,
        artifact_relative,
        maximum=PROGRAM_MAX_ARTIFACT_BYTES,
    )
    collected = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    evidence = {
        "schemaVersion": program_core.EXTERNAL_EVIDENCE_SCHEMA,
        "programId": program_id,
        "gateId": gate_id,
        "contractDigest": context["contractDigest"],
        "gateDigest": context["gateDigest"],
        "kind": gate["evidenceKind"],
        "sha256": digest,
        "size": size,
        "sourcePathDigest": hashlib.sha256(str(artifact).encode("utf-8")).hexdigest(),
        "sourceReference": source_reference,
        "collectedAt": collected.isoformat(),
        "validUntil": (
            collected + _dt.timedelta(minutes=int(gate["maxAgeMinutes"]))
        ).isoformat(),
    }
    evidence["recordDigest"] = hashlib.sha256(
        _canonical_program_payload(evidence)
    ).hexdigest()
    result = _program_call(
        lambda: service.register_evidence(
            program_id, gate_id, evidence, operation_id=operation_id
        )
    )
    return _program_status_integrity(project_path, result)


def _program_running_child_ids(status: dict[str, Any]) -> list[str]:
    active: list[str] = []
    for phase in status.get("phases", []):
        child = phase.get("child")
        if not isinstance(child, dict) or phase.get("completionProof"):
            continue
        child_project = require_project_path(child["projectPath"])
        child_status = _loop_call(
            lambda: _loop_service(child_project).status(child["loopId"])
        )
        if child_status["status"] == "active":
            active.append(child["loopId"])
    return active


def tool_program_pause(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    status = _program_call(lambda: _program_service(project_path).status(program_id))
    active_children = _program_running_child_ids(status)
    if active_children:
        raise ToolError(
            "Pause each active child loop at a checkpoint before pausing the program: "
            + ", ".join(active_children)
        )
    result = _program_call(
        lambda: _program_service(project_path).pause(
            program_id,
            str(args.get("reason") or ""),
            operation_id=operation_id,
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_resume(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    status = tool_program_status(
        {"project_path": str(project_path), "program_id": program_id}
    )
    if status["integrity"]["valid"] is not True:
        raise ToolError("Program context drift requires an approved program revision, not resume.")
    result = _program_call(
        lambda: _program_service(project_path).resume(
            program_id,
            str(args.get("approval_reference") or ""),
            operation_id=operation_id,
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_revise(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    subject, policy, worktree = stable_loop_contract_context(project_path)
    policy_gaps = _program_policy_gaps(args, policy)
    if policy_gaps:
        raise ToolError(
            "Revised program contract does not satisfy policy: "
            + ", ".join(item["id"] for item in policy_gaps)
        )
    attestation = _verified_program_readiness_attestation(
        args.get("program_readiness_receipt"), subject
    )
    result = _program_call(
        lambda: _program_service(project_path).revise(
            str(args.get("program_id") or ""),
            args,
            subject=subject,
            policy_source=policy.get("_sourcePath"),
            policy_digest=subject["policyDigest"],
            common_dir_digest=worktree["commonDirDigest"],
            program_policy=policy.get("program"),
            readiness_attestation=attestation,
            revision_approval_reference=str(
                args.get("revision_approval_reference") or ""
            ),
            operation_id=operation_id,
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_cancel(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    status = _program_call(lambda: _program_service(project_path).status(program_id))
    active_children = _program_running_child_ids(status)
    if active_children:
        raise ToolError(
            "Stop or finalize active child loops before cancelling the program: "
            + ", ".join(active_children)
        )
    result = _program_call(
        lambda: _program_service(project_path).cancel(
            program_id,
            str(args.get("reason") or ""),
            operation_id=operation_id,
        )
    )
    return _program_status_integrity(project_path, result)


def tool_program_finalize(args: dict[str, Any]) -> dict[str, Any]:
    _reject_loop_secret_inputs(args)
    operation_id = _program_operation_id(args)
    project_path = require_project_path(args.get("project_path"))
    program_id = str(args.get("program_id") or "")
    service = _program_service(project_path)
    status = _program_call(lambda: service.status(program_id))
    status = _program_status_integrity(project_path, status, verify_outputs=True)
    if status["integrity"]["valid"] is not True:
        raise ToolError("Program child proofs, outputs, policy, tool, or baseline integrity are not current.")
    if status["status"] not in {"validating", "completed"}:
        raise ToolError("Program is not ready for final acceptance.")
    pseudo_loop = {
        "baselineCommit": status["baselineCommit"],
        "acceptanceCriteria": status["finalAcceptanceCriteria"],
    }
    context = _loop_iteration_evidence(project_path, pseudo_loop, args)
    criteria = loop_core.LoopService._evaluate_criteria(
        {"acceptanceCriteria": status["finalAcceptanceCriteria"]},
        {"completionApprovals": {}},
        context["evidence"],
    )
    remaining = [item["id"] for item in criteria if not item["satisfied"]]
    if remaining:
        raise ToolError(
            "Program final acceptance criteria are not satisfied: "
            + ", ".join(remaining)
        )
    evidence_digest = hashlib.sha256(
        _canonical_program_payload(context["evidence"])
    ).hexdigest()
    result = _program_call(
        lambda: service.finalize(
            program_id,
            expected_contract_digest=status["contractDigest"],
            final_criteria=criteria,
            evidence_digest=evidence_digest,
            project_fingerprint=context["subject"]["projectFingerprint"],
            summary=str(args.get("completion_summary") or ""),
            operation_id=operation_id,
        )
    )
    receipt_subject = evidence_subject(project_path, status["baselineCommit"])
    if any(
        receipt_subject[field] != context["subject"][field]
        for field in ("gitHead", "projectFingerprint", "policyDigest", "toolVersion")
    ):
        raise ToolError(
            "The project changed after program finalization. No completion receipt was issued."
        )
    expires_at = (
        _dt.datetime.now(_dt.timezone.utc)
        + _dt.timedelta(seconds=RECEIPT_MAX_AGE_SECONDS)
    ).replace(microsecond=0).isoformat()
    proof = result.get("completionProof") or {}
    receipt = issue_receipt(
        {
            "kind": "program",
            "schemaVersion": "jstack.program.receipt.v1",
            "expiresAt": expires_at,
            "projectPath": receipt_subject["gitRoot"],
            "gitHead": receipt_subject["gitHead"],
            "projectFingerprint": receipt_subject["projectFingerprint"],
            "baseRef": receipt_subject["baseRef"],
            "baseCommit": receipt_subject["baseCommit"],
            "policyDigest": receipt_subject["policyDigest"],
            "toolVersion": SERVER_VERSION,
            "programId": program_id,
            "contractDigest": status["contractDigest"],
            "completionEvidenceDigest": proof.get("evidenceDigest"),
            "latestEventHash": result["latestEventHash"],
            "phaseProofDigests": proof.get("phaseProofDigests"),
            "passed": True,
        }
    )
    result["completionReceipt"] = receipt
    result["receiptMeaning"] = (
        "Session-local proof that every program phase, final gate, child proof, output, and final acceptance criterion was current. "
        "It authorizes no repository creation, remote change, commit, push, pull request, merge, tag, release, deployment, or production mutation."
    )
    return _program_status_integrity(project_path, result, verify_outputs=True)


LOOP_VERIFIER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["type"],
    "properties": {
        "type": {
            "type": "string",
            "enum": ["qa", "security", "audit", "launch", "review", "artifact", "human"],
        },
        "commandKey": {"type": "string"},
        "profile": {
            "type": "string",
            "enum": ["quick", "standard", "deep", "release"],
        },
        "path": {"type": "string"},
        "sha256": {"type": "string"},
        "approvalKey": {"type": "string"},
        "targetEnvironment": {"type": "string", "maxLength": 64},
        "surfaces": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(launch_core.SURFACE_IDS),
            "items": {
                "type": "string",
                "enum": list(launch_core.SURFACE_IDS),
            },
        },
    },
}

LOOP_CRITERIA_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "description", "verifier"],
        "properties": {
            "id": {"type": "string"},
            "description": {"type": "string"},
            "verifier": LOOP_VERIFIER_SCHEMA,
        },
    },
}

LOOP_LIMITS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "max_iterations": {"type": "integer", "minimum": 1, "maximum": 100},
        "max_no_progress": {"type": "integer", "minimum": 1, "maximum": 20},
        "max_repeated_failure": {"type": "integer", "minimum": 1, "maximum": 20},
        "max_elapsed_minutes": {"type": "integer", "minimum": 5, "maximum": 1440},
        "max_changed_files": {"type": "integer", "minimum": 1, "maximum": 1000},
    },
}

LOOP_GOAL_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "domain_statement": {"type": "string", "maxLength": 1000},
        "domain_tags": {
            "type": "array",
            "maxItems": len(loop_core.GOAL_DOMAIN_TAGS),
            "items": {
                "type": "string",
                "enum": sorted(loop_core.GOAL_DOMAIN_TAGS),
            },
        },
        "stakeholders": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "maxLength": 500},
        },
        "current_state": {"type": "string", "maxLength": 3000},
        "desired_outcome": {"type": "string", "maxLength": 3000},
        "constraints": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "maxLength": 500},
        },
        "constraints_confirmed_empty": {"type": "boolean"},
        "non_goals_confirmed_empty": {"type": "boolean"},
        "assumptions": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "maxLength": 500},
        },
        "context_sources": {
            "type": "array",
            "maxItems": loop_core.MAX_CONTEXT_SOURCES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["repository", "user", "external", "runtime"],
                    },
                    "reference": {"type": "string", "maxLength": 1000},
                    "summary": {"type": "string", "maxLength": 1000},
                },
            },
        },
        "domain_requirements": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "maxLength": 500},
        },
        "open_questions": {
            "type": "array",
            "maxItems": loop_core.MAX_OPEN_QUESTIONS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "maxLength": 64},
                    "question": {"type": "string", "maxLength": 1000},
                    "blocking": {"type": "boolean"},
                },
            },
        },
        "inferred_fields": {
            "type": "array",
            "maxItems": len(loop_core.GOAL_INFERRED_FIELDS),
            "items": {
                "type": "string",
                "enum": sorted(loop_core.GOAL_INFERRED_FIELDS),
            },
        },
    },
}

LOOP_EVIDENCE_PROPERTIES: dict[str, Any] = {
    "qa_receipts": {
        "type": "array",
        "maxItems": LOOP_MAX_QA_RECEIPTS,
        "items": {"type": "string", "maxLength": LOOP_MAX_RECEIPT_CHARS},
    },
    "security_receipt": {"type": "string", "maxLength": LOOP_MAX_RECEIPT_CHARS},
    "launch_receipt": {
        "type": "string",
        "maxLength": LOOP_MAX_RECEIPT_CHARS,
        "description": "A current passing receipt from jstack_launch_finalize, bound to the exact target environment, declared surfaces, policy, catalog, Git state, and loop/program baseline.",
    },
    "audit_receipts": {
        "type": "array",
        "maxItems": LOOP_MAX_AUDIT_RECEIPTS,
        "items": {"type": "string", "maxLength": LOOP_MAX_RECEIPT_CHARS},
    },
    "specialist_handoff_receipt": {
        "type": "string",
        "maxLength": LOOP_MAX_RECEIPT_CHARS,
        "description": "Required for multi-agent loop checkpoints/finalization; returned by jstack_specialist_handoff_check for the current capability contract and Git state.",
    },
}

SPECIALIST_EVIDENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "status", "summary", "references"],
    "properties": {
        "kind": {"type": "string", "minLength": 3, "maxLength": 100},
        "status": {
            "type": "string",
            "enum": ["observed", "passed", "failed", "not-run", "unavailable"],
        },
        "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
        "references": {
            "type": "array",
            "minItems": 1,
            "maxItems": 30,
            "items": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
        "verifier": {"type": "string", "minLength": 1, "maxLength": 500},
    },
}

SPECIALIST_FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "findingId",
        "resolutionKey",
        "disposition",
        "severity",
        "confidence",
        "title",
        "claim",
        "evidenceKinds",
    ],
    "properties": {
        "findingId": {"type": "string", "minLength": 3, "maxLength": 100},
        "resolutionKey": {"type": "string", "minLength": 3, "maxLength": 100},
        "disposition": {
            "type": "string",
            "enum": ["pass", "concern", "block", "not-applicable"],
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical"],
        },
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "title": {"type": "string", "minLength": 1, "maxLength": 300},
        "claim": {"type": "string", "minLength": 1, "maxLength": 3000},
        "evidenceKinds": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": {"type": "string", "minLength": 3, "maxLength": 100},
        },
        "location": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 1000},
                "line": {"type": "integer", "minimum": 1},
            },
        },
    },
}

SPECIALIST_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schemaVersion",
        "status",
        "scopeHandled",
        "evidence",
        "findings",
        "changes",
        "blockers",
        "residualRisk",
        "skippedChecks",
        "recommendedNextAction",
    ],
    "properties": {
        "schemaVersion": {
            "type": "string",
            "enum": ["jstack.specialist.result.v1"],
        },
        "status": {
            "type": "string",
            "enum": ["success", "partial", "blocked", "error"],
        },
        "scopeHandled": {"type": "string", "minLength": 1, "maxLength": 4000},
        "evidence": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": SPECIALIST_EVIDENCE_SCHEMA,
        },
        "findings": {
            "type": "array",
            "maxItems": 100,
            "items": SPECIALIST_FINDING_SCHEMA,
        },
        "changes": {
            "type": "array",
            "maxItems": 200,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "summary"],
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "summary": {"type": "string", "minLength": 1, "maxLength": 1000},
                },
            },
        },
        "blockers": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "summary", "approvalRequired"],
                "properties": {
                    "code": {"type": "string", "minLength": 3, "maxLength": 100},
                    "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
                    "approvalRequired": {"type": "boolean"},
                },
            },
        },
        "residualRisk": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
        "skippedChecks": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["check", "reason", "impact"],
                "properties": {
                    "check": {"type": "string", "minLength": 1, "maxLength": 500},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "impact": {"type": "string", "minLength": 1, "maxLength": 1000},
                },
            },
        },
        "recommendedNextAction": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2000,
        },
    },
}

SPECIALIST_TELEMETRY_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schemaVersion",
        "runId",
        "traceId",
        "spanId",
        "startedAt",
        "completedAt",
        "status",
        "toolCalls",
        "rawContentStored",
    ],
    "properties": {
        "schemaVersion": {
            "type": "string",
            "enum": ["jstack.specialist.telemetry.v1"],
        },
        "runId": {"type": "string", "minLength": 8, "maxLength": 128},
        "traceId": {"type": "string", "minLength": 32, "maxLength": 32},
        "spanId": {"type": "string", "minLength": 16, "maxLength": 16},
        "startedAt": {"type": "string", "minLength": 20, "maxLength": 64},
        "completedAt": {"type": "string", "minLength": 20, "maxLength": 64},
        "status": {
            "type": "string",
            "enum": ["success", "partial", "blocked", "error"],
        },
        "toolCalls": {
            "type": "array",
            "maxItems": 200,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["toolName", "status"],
                "properties": {
                    "toolName": {"type": "string", "minLength": 1, "maxLength": 200},
                    "status": {
                        "type": "string",
                        "enum": ["success", "error", "blocked", "not-run"],
                    },
                    "evidenceRef": {"type": "string", "minLength": 1, "maxLength": 500},
                },
            },
        },
        "durationMs": {"type": "integer", "minimum": 0, "maximum": 86_400_000},
        "inputTokens": {"type": "integer", "minimum": 0, "maximum": 1_000_000_000},
        "outputTokens": {"type": "integer", "minimum": 0, "maximum": 1_000_000_000},
        "rawContentStored": {"type": "boolean"},
    },
}

SPECIALIST_EXPECTED_AGENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["roleId", "capabilityIds"],
    "properties": {
        "roleId": {"type": "string", "minLength": 2, "maxLength": 64},
        "capabilityIds": {
            "type": "array",
            "minItems": 1,
            "maxItems": 8,
            "items": {"type": "string", "minLength": 3, "maxLength": 64},
        },
    },
}

SPECIALIST_RESOLUTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["resolutionKey", "decision", "rationale", "evidenceReferences"],
    "properties": {
        "resolutionKey": {"type": "string", "minLength": 3, "maxLength": 100},
        "decision": {
            "type": "string",
            "enum": ["pass", "concern", "block", "not-applicable"],
        },
        "rationale": {"type": "string", "minLength": 1, "maxLength": 2000},
        "evidenceReferences": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
    },
}

PROGRAM_VERIFIER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["type"],
    "properties": {
        "type": {
            "type": "string",
            "enum": ["qa", "security", "audit", "launch", "review", "artifact"],
        },
        "commandKey": {"type": "string", "maxLength": 200},
        "profile": {
            "type": "string",
            "enum": ["quick", "standard", "deep", "release"],
        },
        "path": {"type": "string", "maxLength": 500},
        "sha256": {"type": "string", "maxLength": 64},
        "targetEnvironment": {"type": "string", "maxLength": 64},
        "surfaces": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(launch_core.SURFACE_IDS),
            "items": {
                "type": "string",
                "enum": list(launch_core.SURFACE_IDS),
            },
        },
    },
}

PROGRAM_CRITERIA_SCHEMA: dict[str, Any] = {
    "type": "array",
    "minItems": 1,
    "maxItems": program_core.MAX_CRITERIA,
    "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "description", "verifier"],
        "properties": {
            "id": {"type": "string", "maxLength": 64},
            "description": {"type": "string", "maxLength": 1000},
            "verifier": PROGRAM_VERIFIER_SCHEMA,
        },
    },
}

PROGRAM_GATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["id", "type", "description"],
    "properties": {
        "id": {"type": "string", "maxLength": 64},
        "type": {"type": "string", "enum": ["human", "external"]},
        "when": {
            "type": "string",
            "enum": ["before_phase", "after_phase", "final"],
        },
        "description": {"type": "string", "maxLength": 1000},
        "required_roles": {
            "type": "array",
            "maxItems": 20,
            "items": {"type": "string", "maxLength": 100},
        },
        "quorum": {"type": "integer", "minimum": 1, "maximum": 20},
        "max_age_minutes": {
            "type": "integer",
            "minimum": 1,
            "maximum": program_core.MAX_ACTIVE_MINUTES,
        },
        "evidence_kind": {"type": "string", "maxLength": 64},
        "required_sha256": {"type": "string", "maxLength": 64},
    },
}

PROGRAM_PHASE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "id",
        "title",
        "goal",
        "acceptance_criteria",
    ],
    "properties": {
        "id": {"type": "string", "maxLength": 64},
        "title": {"type": "string", "maxLength": 200},
        "goal": {"type": "string", "maxLength": 4000},
        "depends_on": {
            "type": "array",
            "maxItems": program_core.MAX_PHASES,
            "items": {"type": "string", "maxLength": 64},
        },
        "execution_mode": {
            "type": "string",
            "enum": ["single-lead", "smart-subagents", "full-team"],
        },
        "autonomy_level": {
            "type": "string",
            "enum": ["L0", "L1", "L2", "L3"],
        },
        "risk_tier": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "allowed_paths": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 500},
        },
        "blocked_actions": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "maxLength": 500},
        },
        "acceptance_criteria": PROGRAM_CRITERIA_SCHEMA,
        "gates": {
            "type": "array",
            "maxItems": program_core.MAX_GATES_PER_PHASE,
            "items": PROGRAM_GATE_SCHEMA,
        },
        "outputs": {
            "type": "array",
            "maxItems": program_core.MAX_OUTPUTS_PER_PHASE,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "path"],
                "properties": {
                    "id": {"type": "string", "maxLength": 64},
                    "path": {"type": "string", "maxLength": 500},
                },
            },
        },
        "parallel_safe": {"type": "boolean"},
        "worktree_required": {"type": "boolean"},
    },
}

PROGRAM_LIMITS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "max_phases": {
            "type": "integer",
            "minimum": 1,
            "maximum": program_core.MAX_PHASES,
        },
        "max_parallel_phases": {
            "type": "integer",
            "minimum": 1,
            "maximum": program_core.MAX_PARALLEL_PHASES,
        },
        "max_active_minutes": {
            "type": "integer",
            "minimum": 1,
            "maximum": program_core.MAX_ACTIVE_MINUTES,
        },
    },
}

PROGRAM_CONTRACT_PROPERTIES: dict[str, Any] = {
    "project_path": {"type": "string"},
    "program_id": {"type": "string", "maxLength": 100},
    "operation_id": {
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$",
    },
    "goal": {"type": "string", "maxLength": 4000},
    "owner": {"type": "string", "maxLength": 200},
    "stakeholders": {
        "type": "array",
        "maxItems": 50,
        "items": {"type": "string", "maxLength": 200},
    },
    "non_goals": {
        "type": "array",
        "maxItems": 50,
        "items": {"type": "string", "maxLength": 500},
    },
    "phases": {
        "type": "array",
        "maxItems": program_core.MAX_PHASES,
        "items": PROGRAM_PHASE_SCHEMA,
    },
    "final_acceptance_criteria": PROGRAM_CRITERIA_SCHEMA,
    "final_gates": {
        "type": "array",
        "maxItems": program_core.MAX_GATES,
        "items": PROGRAM_GATE_SCHEMA,
    },
    "limits": PROGRAM_LIMITS_SCHEMA,
    "blocked_actions": {
        "type": "array",
        "maxItems": 50,
        "items": {"type": "string", "maxLength": 500},
    },
    "confirmed_readiness_digest": {"type": "string", "maxLength": 64},
    "confirmation_reference": {"type": "string", "maxLength": 500},
    "program_readiness_receipt": {
        "type": "string",
        "maxLength": PROGRAM_MAX_RECEIPT_CHARS,
    },
    "revision_approval_reference": {"type": "string", "maxLength": 500},
}


EXTERNAL_ACTION_TARGET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "provider",
        "owner",
        "repository",
        "visibility",
        "remoteName",
        "remoteUrl",
        "branch",
        "tag",
        "exactCommit",
        "targetEnvironment",
    ],
    "properties": {
        "provider": {
            "type": "string",
            "enum": list(authorization_core.PROVIDERS),
        },
        "owner": {"type": "string", "minLength": 1, "maxLength": 500},
        "repository": {"type": "string", "minLength": 1, "maxLength": 100},
        "visibility": {
            "type": "string",
            "enum": list(authorization_core.VISIBILITIES),
        },
        "remoteName": {"type": "string", "minLength": 1, "maxLength": 64},
        "remoteUrl": {"type": "string", "minLength": 1, "maxLength": 1000},
        "branch": {"type": "string", "minLength": 1, "maxLength": 255},
        "tag": {"type": "string", "minLength": 1, "maxLength": 255},
        "exactCommit": {"type": "string", "minLength": 40, "maxLength": 64},
        "targetEnvironment": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
        },
    },
}

EXTERNAL_ACTION_OBSERVATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["target", "providerTargetExists", "source", "observedAt"],
    "properties": {
        "target": EXTERNAL_ACTION_TARGET_SCHEMA,
        "providerTargetExists": {"type": "boolean"},
        "source": {"type": "string", "minLength": 1, "maxLength": 500},
        "observedAt": {"type": "string", "minLength": 1, "maxLength": 100},
    },
}


TOOLS: dict[str, dict[str, Any]] = {
    "gstack_capability_catalog": {
        "description": "Inspect the versioned JStack specialist capability registry or deterministically route bounded capabilities to existing core roles. Capabilities never grant tools, write access, or release authority.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "goal": {"type": "string", "maxLength": 20000},
                "role_ids": {
                    "type": "array",
                    "maxItems": 11,
                    "items": {"type": "string", "maxLength": 64},
                },
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                },
                "query": {"type": "string", "maxLength": 200},
                "include_details": {"type": "boolean"},
            },
        },
        "handler": tool_capability_catalog,
        "readOnlyHint": True,
    },
    "gstack_specialist_result": {
        "description": "Validate one existing JStack role's capability-bound structured result and privacy-safe telemetry, enforce role/write/evidence contracts, bind it to the current Git state, and issue a session-local signed receipt.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "project_path",
                "goal",
                "team_mode",
                "team_role_ids",
                "role_id",
                "capability_ids",
                "result",
                "telemetry",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "goal": {"type": "string", "minLength": 1, "maxLength": 20000},
                "team_mode": {
                    "type": "string",
                    "enum": ["single-lead", "smart-subagents", "full-team"],
                },
                "team_role_ids": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 11,
                    "items": {"type": "string", "maxLength": 64},
                },
                "role_id": {"type": "string", "minLength": 2, "maxLength": 64},
                "capability_ids": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": {"type": "string", "maxLength": 64},
                },
                "explicit_capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                },
                "write_scope": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {"type": "string", "maxLength": 1000},
                },
                "result": SPECIALIST_RESULT_SCHEMA,
                "telemetry": SPECIALIST_TELEMETRY_INPUT_SCHEMA,
            },
        },
        "handler": tool_specialist_result,
        "readOnlyHint": True,
    },
    "gstack_specialist_handoff_check": {
        "description": "Verify complete current specialist receipt coverage, exact capability routing, Git/catalog binding, write ownership, blockers, and contradiction reconciliation before Lead synthesis; issue a handoff receipt only when all gates pass.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "project_path",
                "goal",
                "team_mode",
                "expected_agents",
                "receipts",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "goal": {"type": "string", "minLength": 1, "maxLength": 20000},
                "team_mode": {
                    "type": "string",
                    "enum": ["single-lead", "smart-subagents", "full-team"],
                },
                "expected_agents": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 11,
                    "items": SPECIALIST_EXPECTED_AGENT_SCHEMA,
                },
                "receipts": {
                    "type": "array",
                    "maxItems": SPECIALIST_MAX_RECEIPTS,
                    "items": {
                        "type": "string",
                        "maxLength": SPECIALIST_MAX_RECEIPT_CHARS,
                    },
                },
                "explicit_capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                },
                "resolutions": {
                    "type": "array",
                    "maxItems": 100,
                    "items": SPECIALIST_RESOLUTION_SCHEMA,
                },
            },
        },
        "handler": tool_specialist_handoff_check,
        "readOnlyHint": True,
    },
    "gstack_external_action_challenge": {
        "description": "Create one exact short-lived signed-local challenge for a single repository, Git, release, deployment, or production action. The challenge grants no authority, and broad task or phase approval never satisfies it.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "project_path",
                "action",
                "target",
                "approver_id",
                "approval_reference",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": list(authorization_core.ACTIONS),
                },
                "target": EXTERNAL_ACTION_TARGET_SCHEMA,
                "approver_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "approval_reference": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 500,
                },
                "valid_for_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": authorization_core.MAX_AUTHORIZATION_SECONDS,
                },
            },
        },
        "handler": tool_external_action_challenge,
        "readOnlyHint": False,
    },
    "gstack_external_action_authorize": {
        "description": "Verify an independently signed exact-action attestation against its server challenge and unchanged session, Git, policy, branch, remote, provider, target, and expiry; issue a still-unconsumed one-action receipt.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "project_path",
                "authorization_id",
                "approval_attestation",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "authorization_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
                "approval_attestation": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": EXTERNAL_ACTION_MAX_RECEIPT_CHARS,
                },
            },
        },
        "handler": tool_external_action_authorize,
        "readOnlyHint": False,
    },
    "gstack_external_action_consume": {
        "description": "Destructively consume one exact authorization after a fresh provider observation and unchanged session/Git/policy/branch/remote checks, returning a brief single-operation permit. Replay, retry, substitution, and escalation fail closed.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "project_path",
                "authorization_receipt",
                "action",
                "operation_id",
                "observation",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "authorization_receipt": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": EXTERNAL_ACTION_MAX_RECEIPT_CHARS,
                },
                "action": {
                    "type": "string",
                    "enum": list(authorization_core.ACTIONS),
                },
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
                "observation": EXTERNAL_ACTION_OBSERVATION_SCHEMA,
            },
        },
        "handler": tool_external_action_consume,
        "readOnlyHint": False,
        "destructiveHint": True,
    },
    "gstack_program_goal_readiness": {
        "description": "Assess a multi-phase JStack program contract, validate its dependency DAG and policy-required final gates, ask at most three blocking questions, require exact-digest confirmation, and issue a current readiness receipt.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": PROGRAM_CONTRACT_PROPERTIES,
        },
        "handler": tool_program_goal_readiness,
        "readOnlyHint": True,
    },
    "gstack_program_start": {
        "description": "Create a durable Git-bound Program -> Phase contract above bounded JStack child loops. The program schedules and verifies work but never edits code or authorizes release itself.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "goal",
                "owner",
                "stakeholders",
                "phases",
                "final_acceptance_criteria",
                "program_readiness_receipt",
                "operation_id",
            ],
            "properties": PROGRAM_CONTRACT_PROPERTIES,
        },
        "handler": tool_program_start,
        "readOnlyHint": False,
    },
    "gstack_program_status": {
        "description": "Validate and report durable program state, DAG progress, gates, active-time budget, child completion proofs, policy/tool context, and the next lifecycle decision.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
            },
        },
        "handler": tool_program_status,
        "readOnlyHint": True,
    },
    "gstack_program_next": {
        "description": "Return the next bounded phase set allowed by dependencies, concurrency limits, isolated-worktree declarations, and conservative path-scope conflict checks.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["program_id"],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
            },
        },
        "handler": tool_program_next,
        "readOnlyHint": True,
    },
    "gstack_program_phase_bind": {
        "description": "Bind one safe-scheduler-selected program phase to an exact active JStack child-loop contract in the same Git repository, with inherited blocked actions and linked-worktree enforcement where required.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["program_id", "phase_id", "loop_id", "operation_id"],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "phase_id": {"type": "string", "maxLength": 64},
                "loop_id": {"type": "string", "maxLength": 100},
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
                "child_project_path": {"type": "string"},
            },
        },
        "handler": tool_program_phase_bind,
        "readOnlyHint": False,
    },
    "gstack_program_phase_complete": {
        "description": "Verify a current child-loop completion receipt against durable event-chain state, hash declared phase outputs, and advance only that exact program phase.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "program_id",
                "phase_id",
                "loop_completion_receipt",
                "operation_id",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "phase_id": {"type": "string", "maxLength": 64},
                "loop_completion_receipt": {
                    "type": "string",
                    "maxLength": PROGRAM_MAX_RECEIPT_CHARS,
                },
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_program_phase_complete,
        "readOnlyHint": False,
    },
    "gstack_program_gate_challenge": {
        "description": "Create an exact contract-bound challenge for a configured signed-local human approver. This does not approve the gate; the named person must sign it outside Codex.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "program_id",
                "gate_id",
                "approver_id",
                "decision",
                "approval_reference",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "gate_id": {"type": "string", "maxLength": 64},
                "approver_id": {"type": "string", "maxLength": 64},
                "decision": {
                    "type": "string",
                    "enum": ["approved", "rejected"],
                },
                "approval_reference": {"type": "string", "maxLength": 500},
                "valid_for_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": program_core.MAX_ACTIVE_MINUTES,
                },
            },
        },
        "handler": tool_program_gate_challenge,
        "readOnlyHint": True,
    },
    "gstack_program_gate_resolve": {
        "description": "Verify a signed-local identity token against the current program, gate, role, quorum, decision, and expiry, then record only its digest-bound approval metadata.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "program_id",
                "gate_id",
                "approval_attestation",
                "operation_id",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "gate_id": {"type": "string", "maxLength": 64},
                "approval_attestation": {
                    "type": "string",
                    "maxLength": PROGRAM_MAX_RECEIPT_CHARS,
                },
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_program_gate_resolve,
        "readOnlyHint": False,
    },
    "gstack_program_evidence_register": {
        "description": "Hash and register a bounded external artifact for an exact evidence gate, with provenance, freshness, and downstream invalidation on replacement.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "program_id",
                "gate_id",
                "artifact_path",
                "source_reference",
                "operation_id",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "gate_id": {"type": "string", "maxLength": 64},
                "artifact_path": {"type": "string"},
                "source_reference": {"type": "string", "maxLength": 500},
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_program_evidence_register,
        "readOnlyHint": False,
    },
    "gstack_program_pause": {
        "description": "Pause a program without consuming active-time budget after every active child loop has reached a safe checkpoint and released its write lease.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["program_id", "reason", "operation_id"],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "reason": {"type": "string", "maxLength": 1000},
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_program_pause,
        "readOnlyHint": False,
    },
    "gstack_program_resume": {
        "description": "Resume a manually paused program only after policy, tool, repository, baseline, and durable child-proof context are revalidated.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["program_id", "approval_reference", "operation_id"],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "approval_reference": {"type": "string", "maxLength": 500},
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_program_resume,
        "readOnlyHint": False,
    },
    "gstack_program_revise": {
        "description": "Create an exact-digest approved program contract revision, preserve unaffected phase proof, invalidate changed phases plus transitive dependants, and clear gate records bound to the prior digest.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "program_id",
                "goal",
                "owner",
                "stakeholders",
                "phases",
                "final_acceptance_criteria",
                "program_readiness_receipt",
                "revision_approval_reference",
                "operation_id",
            ],
            "properties": PROGRAM_CONTRACT_PROPERTIES,
        },
        "handler": tool_program_revise,
        "readOnlyHint": False,
    },
    "gstack_program_cancel": {
        "description": "Cancel a durable program after all active child loops are stopped or finalized, preserving its auditable state and releasing the orchestration slot.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["program_id", "reason", "operation_id"],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "reason": {"type": "string", "maxLength": 1000},
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_program_cancel,
        "readOnlyHint": False,
    },
    "gstack_program_finalize": {
        "description": "Revalidate every child proof and output plus current final QA, security, launch, release-audit, review, artifact, and gate evidence before issuing a session-local program completion receipt.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["program_id", "completion_summary", "operation_id"],
            "properties": {
                "project_path": {"type": "string"},
                "program_id": {"type": "string", "maxLength": 100},
                "completion_summary": {"type": "string", "maxLength": 4000},
                "operation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                },
                **LOOP_EVIDENCE_PROPERTIES,
            },
        },
        "handler": tool_program_finalize,
        "readOnlyHint": False,
    },
    "gstack_loop_goal_readiness": {
        "description": "Assess a partial or complete JStack loop goal contract, return at most three targeted context questions, require exact-digest confirmation when ambiguity or risk warrants it, and issue a session-local readiness receipt for the current Git state.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "project_path": {"type": "string"},
                "loop_id": {"type": "string"},
                "goal": {"type": "string"},
                "execution_mode": {
                    "type": "string",
                    "enum": ["single-lead", "smart-subagents", "full-team"],
                },
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "Optional explicit capabilities bound into the loop readiness digest and durable contract.",
                },
                "autonomy_level": {
                    "type": "string",
                    "enum": ["L0", "L1", "L2", "L3"],
                },
                "risk_tier": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "acceptance_criteria": LOOP_CRITERIA_SCHEMA,
                "non_goals": {"type": "array", "items": {"type": "string"}},
                "allowed_paths": {"type": "array", "items": {"type": "string"}},
                "blocked_actions": {"type": "array", "items": {"type": "string"}},
                "limits": LOOP_LIMITS_SCHEMA,
                "token_budget": {"type": "integer", "minimum": 1},
                "goal_context": LOOP_GOAL_CONTEXT_SCHEMA,
                "mode_approval_reference": {"type": "string"},
                "autonomy_approval_reference": {"type": "string"},
                "risk_approval_reference": {"type": "string"},
                "protected_path_approval": {"type": "string"},
                "confirmed_readiness_digest": {"type": "string", "maxLength": 64},
                "confirmation_reference": {"type": "string", "maxLength": 500},
            },
        },
        "handler": tool_loop_goal_readiness,
        "readOnlyHint": True,
    },
    "gstack_loop_start": {
        "description": "Create a versioned, Git-bound JStack loop contract with bounded autonomy, explicit execution mode, acceptance evidence, path scope, and circuit breakers. Codex Goal mode remains the continuation engine.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "goal",
                "execution_mode",
                "autonomy_level",
                "risk_tier",
                "acceptance_criteria",
                "allowed_paths",
                "goal_context",
                "goal_readiness_receipt",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "goal": {"type": "string"},
                "execution_mode": {
                    "type": "string",
                    "enum": ["single-lead", "smart-subagents", "full-team"],
                },
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "Must match the capability selection used for goal readiness.",
                },
                "autonomy_level": {
                    "type": "string",
                    "enum": ["L0", "L1", "L2", "L3"],
                },
                "risk_tier": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "acceptance_criteria": LOOP_CRITERIA_SCHEMA,
                "non_goals": {"type": "array", "items": {"type": "string"}},
                "allowed_paths": {"type": "array", "items": {"type": "string"}},
                "blocked_actions": {"type": "array", "items": {"type": "string"}},
                "limits": LOOP_LIMITS_SCHEMA,
                "token_budget": {"type": "integer", "minimum": 1},
                "goal_context": LOOP_GOAL_CONTEXT_SCHEMA,
                "goal_readiness_receipt": {
                    "type": "string",
                    "maxLength": LOOP_MAX_RECEIPT_CHARS,
                },
                "mode_approval_reference": {"type": "string"},
                "autonomy_approval_reference": {"type": "string"},
                "risk_approval_reference": {"type": "string"},
                "protected_path_approval": {"type": "string"},
            },
        },
        "handler": tool_loop_start,
        "readOnlyHint": False,
    },
    "gstack_loop_status": {
        "description": "Validate and report a durable JStack loop contract, hash-chained state, convergence status, circuit breaker, current Git binding, and remaining criteria. Omit loop_id to discover the active or latest loop for the repository.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "project_path": {"type": "string"},
                "loop_id": {"type": "string"},
            },
        },
        "handler": tool_loop_status,
        "readOnlyHint": True,
    },
    "gstack_loop_checkpoint": {
        "description": "Record one bounded loop iteration, revalidate current JStack evidence, enforce scope and policy, detect stagnation/repeated failures/oscillation, and return continue, finalize, approval, or stop guidance.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["loop_id", "iteration_summary"],
            "properties": {
                "project_path": {"type": "string"},
                "loop_id": {"type": "string"},
                "iteration_summary": {"type": "string"},
                "failure_signature": {"type": "string"},
                "blocker": {"type": "string"},
                **LOOP_EVIDENCE_PROPERTIES,
            },
        },
        "handler": tool_loop_checkpoint,
        "readOnlyHint": False,
    },
    "gstack_loop_revise": {
        "description": "Create an approved new revision of an active loop contract, invalidate stale completion evidence, add named approval references, and resume from a circuit-breaker stop.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["loop_id"],
            "properties": {
                "project_path": {"type": "string"},
                "loop_id": {"type": "string"},
                "goal": {"type": "string"},
                "execution_mode": {
                    "type": "string",
                    "enum": ["single-lead", "smart-subagents", "full-team"],
                },
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "Optional revised explicit capability ids; changing them is a material contract revision.",
                },
                "autonomy_level": {
                    "type": "string",
                    "enum": ["L0", "L1", "L2", "L3"],
                },
                "risk_tier": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "acceptance_criteria": LOOP_CRITERIA_SCHEMA,
                "non_goals": {"type": "array", "items": {"type": "string"}},
                "allowed_paths": {"type": "array", "items": {"type": "string"}},
                "blocked_actions": {"type": "array", "items": {"type": "string"}},
                "limits": LOOP_LIMITS_SCHEMA,
                "token_budget": {"type": "integer", "minimum": 1},
                "goal_context": LOOP_GOAL_CONTEXT_SCHEMA,
                "goal_readiness_receipt": {
                    "type": "string",
                    "maxLength": LOOP_MAX_RECEIPT_CHARS,
                },
                "mode_approval_reference": {"type": "string"},
                "autonomy_approval_reference": {"type": "string"},
                "risk_approval_reference": {"type": "string"},
                "protected_path_approval": {"type": "string"},
                "revision_approval_reference": {"type": "string"},
                "approval_updates": {
                    "type": "object",
                    "description": "Map human acceptance approval keys to explicit external references.",
                },
            },
        },
        "handler": tool_loop_revise,
        "readOnlyHint": False,
    },
    "gstack_loop_stop": {
        "description": "Stop an active JStack loop, append the reason to its durable event chain, and release its repository write lease.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["loop_id", "reason"],
            "properties": {
                "project_path": {"type": "string"},
                "loop_id": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        "handler": tool_loop_stop,
        "readOnlyHint": False,
    },
    "gstack_loop_finalize": {
        "description": "Revalidate every loop criterion against the current Git state and issue a session-local completion receipt. This never authorizes any repository, Git, release, deployment, or production action.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["loop_id", "completion_summary"],
            "properties": {
                "project_path": {"type": "string"},
                "loop_id": {"type": "string"},
                "completion_summary": {"type": "string"},
                **LOOP_EVIDENCE_PROPERTIES,
            },
        },
        "handler": tool_loop_finalize,
        "readOnlyHint": False,
    },
    "gstack_mastery_status": {
        "description": "Show the current JStack learner stage, advancement evidence, and next deliberate-practice drill.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "track": {"type": "string", "enum": ["engineering", "audit", "loop"], "default": "engineering"}
            },
        },
        "handler": tool_mastery_status,
        "readOnlyHint": True,
    },
    "gstack_mastery_start": {
        "description": "Initialize the local JStack mastery profile at Stage 0 without overwriting an existing profile.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "learner_name": {"type": "string", "default": "Jay"},
                "track": {"type": "string", "enum": ["engineering", "audit", "loop"], "default": "engineering"},
            },
        },
        "handler": tool_mastery_start,
        "readOnlyHint": False,
    },
    "gstack_mastery_record": {
        "description": "Record a mastery attempt from hashed artifacts, commit-bound QA/security receipts, assistance level, and independently cited rubric evidence; advancement is derived by policy.",
        "inputSchema": {
            "type": "object",
            "required": ["project_path", "stage", "drill_id", "assistance_level", "assessor", "assessor_citations", "assessment", "artifacts"],
            "properties": {
                "project_path": {"type": "string"},
                "track": {"type": "string", "enum": ["engineering", "audit", "loop"], "default": "engineering"},
                "stage": {"type": "integer", "minimum": 0, "maximum": 9},
                "drill_id": {"type": "string"},
                "assistance_level": {"type": "string", "enum": ["observed", "guided", "checklist", "independent", "independent_teach"]},
                "assessor": {"type": "string"},
                "assessor_citations": {"type": "array", "items": {"type": "string"}},
                "assessment": {
                    "type": "object",
                    "required": ["correctness", "evidence", "safety", "judgment", "explanation"],
                    "properties": {
                        "correctness": {"type": "number", "minimum": 0, "maximum": 100},
                        "evidence": {"type": "number", "minimum": 0, "maximum": 100},
                        "safety": {"type": "number", "minimum": 0, "maximum": 100},
                        "judgment": {"type": "number", "minimum": 0, "maximum": 100},
                        "explanation": {"type": "number", "minimum": 0, "maximum": 100}
                    }
                },
                "artifacts": {"type": "object", "description": "Map each stage requiredArtifact name to a project-relative file or directory."},
                "qa_receipts": {"type": "array", "items": {"type": "string"}, "default": []},
                "security_receipt": {"type": "string"},
                "audit_receipt": {"type": "string"},
                "hard_gate_failures": {"type": "array", "items": {"type": "string"}, "default": []},
                "blind_capstone": {
                    "type": "boolean",
                    "default": False,
                    "description": "Engineering Stage 9 compatibility field. Audit and loop Stage 9 require a signed assessor attestation.",
                },
                "assessor_attestation": {
                    "type": "object",
                    "description": "Audit or loop Stage 9 assessor-signed attestation bound to the exact attempt digest and a distinct unseen challenge subject. A caller boolean cannot establish blindness.",
                },
                "capstone_results": {
                    "type": "object",
                    "description": "Engineering Stage 9 aggregate results only. Audit and loop Stage 9 derive metrics from required hashed evaluation artifacts and reject this field."
                }
            }
        },
        "handler": tool_mastery_record,
        "readOnlyHint": False,
    },
    "gstack_runtime_status": {
        "description": "Prove that the JStack MCP is mounted and report its transport, version, session, and optional Git or artifact-only project binding without requiring a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "description": "Optional existing project or orchestration directory to classify as git-backed or artifact-only."}
            },
        },
        "handler": tool_runtime_status,
        "readOnlyHint": True,
    },
    "gstack_detect_project": {
        "description": "Detect JStack installation, project config, test commands, and either a Git-backed or explicit artifact-only binding for an existing directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"project_path": {"type": "string", "description": "Absolute or relative project directory. Defaults to MCP process cwd."}},
        },
        "handler": tool_detect_project,
        "readOnlyHint": True,
    },
    "gstack_list_skills": {
        "description": "List installed gstack skills with descriptions. Supports simple query filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Optional search text such as qa, security, design or review."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 40},
            },
        },
        "handler": tool_list_skills,
        "readOnlyHint": True,
    },
    "gstack_read_skill": {
        "description": "Read a specific installed gstack skill by skill name or directory, for example qa, review, health, cso.",
        "inputSchema": {
            "type": "object",
            "required": ["skill_name"],
            "properties": {
                "skill_name": {"type": "string"},
                "max_chars": {"type": "integer", "minimum": 1000, "maximum": 50000, "default": 20000},
            },
        },
        "handler": tool_read_skill,
        "readOnlyHint": True,
    },
    "gstack_plan": {
        "description": "Create a gstack-oriented execution and mastery plan for a project goal. Non-Git directories receive artifact-only planning while Git-backed evidence and release tools remain blocked.",
        "inputSchema": {
            "type": "object",
            "required": ["goal"],
            "properties": {
                "goal": {"type": "string"},
                "project_path": {"type": "string"},
                "quality_level": {"type": "string", "enum": ["standard", "enterprise"], "default": "enterprise"},
                "team_mode": {"type": "string", "enum": ["single-lead", "smart-subagents", "full-team"], "default": "single-lead"},
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "Optional explicit specialist capability ids; they remain bounded by the selected core roles.",
                },
                "mastery_mode": {"type": "boolean", "default": True, "description": "When true, include staged training objectives, benchmarks, anti-slop checklist, review rubric, and next drill."},
                "learning_mode": {"type": "string", "enum": ["off", "embedded", "coach", "assessment"], "default": "embedded"},
            },
        },
        "handler": tool_plan,
        "readOnlyHint": True,
    },
    "gstack_team_plan": {
        "description": "Create a lead-agent, smart-subagents, or full-team dispatch plan for a goal, including roles, coordination packet, evidence requirements, and anti-swarm safety rules.",
        "inputSchema": {
            "type": "object",
            "required": ["goal"],
            "properties": {
                "goal": {"type": "string"},
                "quality_level": {"type": "string", "enum": ["standard", "enterprise"], "default": "enterprise"},
                "team_mode": {"type": "string", "enum": ["auto", "single-lead", "smart-subagents", "full-team"], "default": "auto"},
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "Optional explicit capability ids to add when allowed for the selected roles.",
                },
            },
        },
        "handler": tool_team_plan,
        "readOnlyHint": True,
    },
    "gstack_dispatch_check": {
        "description": "Validate a proposed multi-agent dispatch plan for lead accountability, coordination packet, max specialist count, write-scope overlap, and blocked actions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "goal": {"type": "string"},
                "team_mode": {"type": "string", "enum": ["auto", "single-lead", "smart-subagents", "full-team"], "default": "auto"},
                "team": {"type": "object", "description": "Object containing an agents array, usually from gstack_team_plan."},
                "agents": {"type": "array", "items": {"type": "object"}, "description": "Alternative direct agent list."},
                "max_specialists": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
                "lead_justification": {"type": "string"},
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "The same explicit capability id list used to create the team plan.",
                },
                "coordination_packet": {
                    "type": "object",
                    "description": "The actual coordination packet. Its required fields, roles, and file ownership are validated.",
                },
                "explicit_release_requested": {"type": "boolean", "default": False, "description": "Confirms only that release-classified team planning was requested; never external-action authority."},
            },
        },
        "handler": tool_dispatch_check,
        "readOnlyHint": True,
    },
    "gstack_policy_check": {
        "description": "Read project gstack policy, classify risk, check protected changed paths, and return enterprise blockers/warnings without modifying files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "description": "Optional comparison ref. Defaults to upstream/main/master discovery."},
                "goal": {"type": "string"},
                "target_environment": {"type": "string", "default": "local"},
                "explicit_release_requested": {"type": "boolean", "default": False, "description": "Confirms only that release policy assessment was requested; never external-action authority."},
                "protected_path_approval": {"type": "string"},
            },
        },
        "handler": tool_policy_check,
        "readOnlyHint": True,
    },
    "gstack_preflight": {
        "description": "Run enterprise preflight gates: policy check, project health, diff hygiene, test command discovery, and optional secret scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "description": "Optional comparison ref. Defaults to upstream/main/master discovery."},
                "goal": {"type": "string"},
                "target_environment": {"type": "string", "default": "local"},
                "explicit_release_requested": {"type": "boolean", "default": False, "description": "Confirms only that release preflight was requested; never external-action authority."},
                "protected_path_approval": {"type": "string"},
                "strict": {"type": "boolean", "default": True},
                "run_secret_scan": {"type": "boolean", "default": True},
                "max_files": {"type": "integer", "minimum": 100, "maximum": 10000, "default": 2000},
            },
        },
        "handler": tool_preflight,
        "readOnlyHint": True,
    },
    "gstack_health": {
        "description": "Collect safe project health signals: git status, branch, docs, stack markers and detected test commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "description": "Optional comparison ref. Defaults to upstream/main/master discovery."},
            },
        },
        "handler": tool_health,
        "readOnlyHint": True,
    },
    "gstack_review": {
        "description": "Run safe local review checks: git status, diff stat, changed files and git diff --check.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string"},
            },
        },
        "handler": tool_review,
        "readOnlyHint": True,
    },
    "gstack_security_audit": {
        "description": "Run a bounded local heuristic secret/security scan with common credential patterns and production caveats.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "description": "Optional release-range base for historical secret scanning."},
                "max_files": {"type": "integer", "minimum": 100, "maximum": 10000, "default": 2000},
                "max_file_bytes": {"type": "integer", "minimum": 10000, "maximum": 10000000, "default": 2000000},
            },
        },
        "handler": tool_security_audit,
        "readOnlyHint": True,
    },
    "gstack_audit": {
        "description": "Start a read-only evidence-bound audit session, collect bounded deterministic evidence, discover curated offline adapters, and optionally run only exactly approved adapter subjects.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "project_path": {"type": "string"},
                "profile": {
                    "type": "string",
                    "enum": ["quick", "standard", "deep", "release"],
                },
                "scope": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Repository-relative POSIX paths. Omit for the profile default.",
                },
                "focus": {
                    "type": "string",
                    "maxLength": 4000,
                    "description": "Optional audit focus used for deterministic specialist capability and domain routing.",
                },
                "capability_ids": {
                    "type": "array",
                    "maxItems": 14,
                    "items": {"type": "string", "maxLength": 64},
                    "description": "Optional explicit audit capability ids, constrained to read-only audit roles.",
                },
                "base_ref": {"type": "string"},
                "fail_on": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical", "none"],
                },
                "adapter_approvals": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Exact approval objects copied from applicable adapter plan subjects. Omit for discovery only.",
                },
                "adapter_timeout_sec": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 300,
                    "default": 120,
                },
            },
        },
        "handler": tool_audit,
        "readOnlyHint": False,
    },
    "gstack_audit_finalize": {
        "description": "Validate a signed audit session, exact subject coverage, structured findings, source ranges, suppressions, and result semantics; emit JSON, Markdown, SARIF, and an eligible Git-bound audit receipt.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "audit_session_token",
                "domain_coverage",
                "evidence",
                "findings",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "audit_session_token": {"type": "string"},
                "domain_coverage": {
                    "description": "Object or array containing exact audit-domain coverage entries."
                },
                "evidence": {"type": "array", "items": {"type": "object"}},
                "findings": {"type": "array", "items": {"type": "object"}},
                "suppressions": {"type": "array", "items": {"type": "object"}},
                "qa_receipts": {"type": "array", "items": {"type": "string"}},
                "errors": {"type": "array", "items": {"type": "string"}},
                "formats": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["json", "markdown", "sarif"]},
                },
                "evaluated_at": {
                    "type": "string",
                    "description": "Deprecated compatibility field. Suppression expiry is always evaluated against server time.",
                },
            },
        },
        "handler": tool_audit_finalize,
        "readOnlyHint": True,
    },
    "gstack_qa": {
        "description": "Discover test/build commands. Execution requires explicit trust approval bound to the exact git revision and project fingerprint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "description": "Comparison base bound into the QA receipt."},
                "run": {"type": "boolean", "default": False},
                "command_key": {"type": "string", "description": "Required only when run=true. Use output allowedCommands keys."},
                "timeout_sec": {"type": "integer", "minimum": 10, "maximum": 600, "default": 120},
                "execution_approved": {"type": "boolean", "default": False, "description": "Required when run=true; acknowledges repository-controlled code execution."},
                "trusted_revision": {"type": "string", "description": "Exact gitHead returned by discovery."},
                "trusted_project_fingerprint": {"type": "string", "description": "Exact projectFingerprint returned by discovery."},
                "trusted_policy_digest": {"type": "string", "description": "Exact policyDigest returned by discovery."},
            },
        },
        "handler": tool_qa,
        "readOnlyHint": False,
    },
    "gstack_context_save": {
        "description": "Save a concise project handoff context under ~/.jstack/mcp-context for future restoration.",
        "inputSchema": {
            "type": "object",
            "required": ["summary"],
            "properties": {
                "project_path": {"type": "string"},
                "label": {"type": "string"},
                "summary": {"type": "string"},
                "decisions": {"type": "array", "items": {"type": "string"}},
                "next_steps": {"type": "array", "items": {"type": "string"}},
                "files_touched": {"type": "array", "items": {"type": "string"}},
            },
        },
        "handler": tool_context_save,
        "readOnlyHint": False,
    },
    "gstack_context_restore": {
        "description": "Restore the latest project handoff context saved by gstack_context_save.",
        "inputSchema": {"type": "object", "properties": {"project_path": {"type": "string"}}},
        "handler": tool_context_restore,
        "readOnlyHint": True,
    },
    "gstack_ship_check": {
        "description": "Run a pre-ship readiness summary using safe health and review checks.",
        "inputSchema": {
            "type": "object",
            "required": ["base_ref"],
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string"},
                "qa_receipts": {"type": "array", "items": {"type": "string"}, "default": []},
            },
        },
        "handler": tool_ship_check,
        "readOnlyHint": True,
    },
    "gstack_launch_assess": {
        "description": "Create a commit-bound, applicability-aware launch contract from the versioned 37-control catalogue. This assessment performs no network request or external action.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "base_ref",
                "surfaces",
                "target_environment",
                "profile_owner",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 500,
                },
                "surfaces": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": len(launch_core.SURFACE_IDS),
                    "items": {
                        "type": "string",
                        "enum": list(launch_core.SURFACE_IDS),
                    },
                },
                "target_environment": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": 64,
                },
                "target_url": {
                    "type": "string",
                    "maxLength": 2000,
                },
                "profile_owner": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                },
                "profile_reference": {
                    "type": "string",
                    "maxLength": 500,
                },
            },
        },
        "handler": tool_launch_assess,
        "readOnlyHint": True,
    },
    "gstack_launch_evidence_register": {
        "description": "Hash and register one bounded launch-evidence artifact against an exact selected control. JStack does not return artifact content or independently certify the named verifier's semantic claim.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "launch_session_token",
                "control_id",
                "evidence_kind",
                "outcome",
                "artifact_path",
                "verifier",
                "source_reference",
                "summary",
            ],
            "properties": {
                "project_path": {"type": "string"},
                "launch_session_token": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": LAUNCH_MAX_RECEIPT_CHARS,
                },
                "control_id": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 80,
                },
                "evidence_kind": {
                    "type": "string",
                    "enum": list(launch_core.EVIDENCE_KINDS),
                },
                "outcome": {
                    "type": "string",
                    "enum": ["pass", "fail", "incomplete", "not-applicable"],
                },
                "artifact_path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2000,
                },
                "verifier": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                },
                "source_reference": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 500,
                },
                "summary": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 2000,
                },
                "observed_at": {
                    "type": "string",
                    "maxLength": 100,
                },
            },
        },
        "handler": tool_launch_evidence_register,
        "readOnlyHint": True,
    },
    "gstack_launch_finalize": {
        "description": "Finalize the selected launch controls fail-closed and issue a current release-consumable launch receipt. Blocker controls cannot be waived; readiness never authorizes an external action.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["launch_session_token", "evidence_receipts"],
            "properties": {
                "project_path": {"type": "string"},
                "launch_session_token": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": LAUNCH_MAX_RECEIPT_CHARS,
                },
                "evidence_receipts": {
                    "type": "array",
                    "maxItems": LAUNCH_MAX_RECEIPTS,
                    "items": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": LAUNCH_MAX_RECEIPT_CHARS,
                    },
                },
                "waivers": {
                    "type": "array",
                    "maxItems": LAUNCH_MAX_RECEIPTS,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "control_id",
                            "owner",
                            "reason",
                            "approval_reference",
                            "expires_at",
                            "compensating_control",
                            "residual_risk",
                        ],
                        "properties": {
                            "control_id": {"type": "string", "maxLength": 80},
                            "owner": {"type": "string", "maxLength": 200},
                            "reason": {"type": "string", "maxLength": 1000},
                            "approval_reference": {"type": "string", "maxLength": 500},
                            "expires_at": {"type": "string", "maxLength": 100},
                            "compensating_control": {"type": "string", "maxLength": 1000},
                            "residual_risk": {"type": "string", "maxLength": 1000},
                        },
                    },
                },
            },
        },
        "handler": tool_launch_finalize,
        "readOnlyHint": True,
    },
    "gstack_release_readiness": {
        "description": "Assess production-style release evidence with strict preflight, ship check, QA, security, applicability-aware launch assurance, conditional release audit, request/reference, rollback, monitoring, and canary inputs. Even ready=true returns executionAuthorized=false and never replaces exact external-action authorization.",
        "inputSchema": {
            "type": "object",
            "required": ["base_ref"],
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "description": "Explicit trusted comparison base for the release delta."},
                "goal": {"type": "string"},
                "target_environment": {"type": "string", "default": "production"},
                "explicit_release_requested": {"type": "boolean", "default": False, "description": "Confirms only that this readiness assessment was requested; never release authority."},
                "approved_by": {"type": "string"},
                "approval_reference": {"type": "string"},
                "security_reviewed_by": {"type": "string"},
                "protected_path_approval": {"type": "string"},
                "rollback_plan": {"type": "string"},
                "monitoring_plan": {"type": "string"},
                "canary_plan": {"type": "string"},
                "run_secret_scan": {"type": "boolean", "default": True},
                "qa_receipts": {"type": "array", "items": {"type": "string"}, "default": []},
                "security_receipt": {"type": "string"},
                "audit_receipt": {"type": "string"},
                "launch_receipt": {
                    "type": "string",
                    "maxLength": LAUNCH_MAX_RECEIPT_CHARS,
                },
            },
        },
        "handler": tool_release_readiness,
        "readOnlyHint": True,
    },
    "gstack_quant_backtest_review": {
        "description": "Review trading/EA backtest evidence for data provenance, model quality, cost assumptions, sample split, parameter freeze, and edge-validation blockers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "report_path": {"type": "string"},
                "strict": {"type": "boolean", "default": True},
                "evidence": {
                    "type": "object",
                    "description": "Backtest evidence such as symbol, timeframe, date_range, data_source, spread_model, commission_model, slippage_model, source_version, settings_file, out_of_sample, walk_forward, drawdown_stress_test.",
                },
            },
        },
        "handler": tool_quant_backtest_review,
        "readOnlyHint": True,
    },
}


for _name, _meta in list(TOOLS.items()):
    if _name.startswith("gstack_"):
        _alias = "jstack_" + _name[len("gstack_") :]
        if _alias not in TOOLS:
            _alias_meta = dict(_meta)
            _alias_meta["description"] = str(_alias_meta["description"]).replace("gstack", "jstack").replace("Gstack", "JStack")
            TOOLS[_alias] = _alias_meta


def tool_definitions() -> list[dict[str, Any]]:
    definitions = []
    for name, meta in TOOLS.items():
        if name.startswith("gstack_"):
            continue
        definitions.append(
            {
                "name": name,
                "description": meta["description"],
                "inputSchema": meta["inputSchema"],
                "annotations": {
                    "readOnlyHint": bool(meta.get("readOnlyHint", True)),
                    "destructiveHint": bool(meta.get("destructiveHint", False)),
                    "openWorldHint": False,
                },
            }
        )
    return definitions


def mcp_result(data: Any) -> dict[str, Any]:
    text_payload = data
    if isinstance(data, dict) and data.get("schemaVersion") == "jstack.audit.finalization.v1":
        text_payload = {
            "schemaVersion": data["schemaVersion"],
            "executiveSummary": data.get("executiveSummary"),
            "releaseDecision": data.get("releaseDecision"),
            "requestedFormats": data.get("requestedFormats"),
            "gitBoundReceiptAvailable": data.get("gitBoundReceiptAvailable"),
            "releaseCertificationAvailable": data.get("releaseCertificationAvailable"),
            "detail": "Requested audit artifacts are available in structuredContent.",
        }
    return {
        "content": [{"type": "text", "text": json_text(text_payload)}],
        "structuredContent": data,
    }


def handle_request(message: dict[str, Any]) -> Optional[dict[str, Any]]:
    global _MCP_INITIALIZED
    method = message.get("method")
    request_id = message.get("id")
    raw_params = message.get("params", {})
    params = raw_params if raw_params is not None else {}
    try:
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Invalid JSON-RPC request."}}
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "JSON-RPC params must be an object."}}
        if method == "initialize":
            if _MCP_INITIALIZED:
                raise ToolError("MCP server is already initialized.")
            requested_version = str(params.get("protocolVersion") or PROTOCOL_VERSION)
            negotiated_version = requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
            _MCP_INITIALIZED = True
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": negotiated_version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }
        if method == "notifications/initialized":
            return None
        if not _MCP_INITIALIZED:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32002, "message": "MCP server must be initialized before this method."},
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tool_definitions()}}
        if method == "tools/call":
            name = params.get("name")
            raw_arguments = params.get("arguments", {})
            arguments = {} if raw_arguments is None else raw_arguments
            if name not in TOOLS:
                raise ToolError(f"Unknown tool: {name}")
            if not isinstance(arguments, dict):
                raise InputError("Tool arguments must be an object.")
            validate_schema_value(arguments, TOOLS[name]["inputSchema"])
            data = TOOLS[name]["handler"](arguments)
            return {"jsonrpc": "2.0", "id": request_id, "result": mcp_result(data)}
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"Unsupported MCP method: {method}"},
        }
    except InputError as exc:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32602, "message": str(exc)},
        }
    except ToolError as exc:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32000, "message": str(exc)},
        }
    except Exception as exc:  # pragma: no cover - defensive boundary
        print(traceback.format_exc(), file=sys.stderr)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32603, "message": f"Internal error: {exc}"},
        }


def read_message() -> Optional[dict[str, Any]]:
    while True:
        line = sys.stdin.buffer.readline(10_000_001)
        if not line:
            return None
        if len(line) > 10_000_000 or (len(line) == 10_000_000 and not line.endswith(b"\n")):
            raise ToolError("MCP message exceeds the 10 MB safety limit.")
        stripped = line.strip()
        if not stripped:
            continue
        message = json.loads(stripped.decode("utf-8"))
        if not isinstance(message, dict):
            raise ToolError("MCP message must be a JSON object.")
        return message


def write_message(message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def main() -> int:
    while True:
        try:
            message = read_message()
        except (json.JSONDecodeError, UnicodeDecodeError, ToolError) as exc:
            write_message({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
            continue
        if message is None:
            return 0
        response = handle_request(message)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    raise SystemExit(main())
