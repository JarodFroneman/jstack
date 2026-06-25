#!/usr/bin/env python3
"""Local stdio MCP server for controlled gstack workflow access.

This server intentionally avoids arbitrary shell execution. Tools expose
project detection, skill discovery, review/QA planning, lightweight health
checks, security scanning, and context save/restore.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any, Callable


SERVER_NAME = "gstack-mcp"
SERVER_VERSION = "0.5.0"
PROTOCOL_VERSION = "2024-11-05"
MAX_OUTPUT_CHARS = 12_000

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


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def truncate(value: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n... truncated {len(value) - limit} chars"


def json_text(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def expand_path(path: str | None) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    return Path.cwd().resolve()


def require_project_path(path: str | None = None) -> Path:
    project_path = expand_path(path)
    if not project_path.exists():
        raise ToolError(f"Project path does not exist: {project_path}")
    if not project_path.is_dir():
        raise ToolError(f"Project path must be a directory: {project_path}")
    return project_path


def safe_run(args: list[str], cwd: Path, timeout: int = 20) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": 127,
            "stdout": "",
            "stderr": f"Command not found: {args[0]}",
            "args": args,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": 124,
            "stdout": truncate(exc.stdout or ""),
            "stderr": truncate((exc.stderr or "") + f"\nTimed out after {timeout}s"),
            "args": args,
        }
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": truncate(completed.stdout or ""),
        "stderr": truncate(completed.stderr or ""),
        "args": args,
    }


def git_root(project_path: Path) -> str | None:
    result = safe_run(["git", "rev-parse", "--show-toplevel"], project_path, timeout=8)
    if result["ok"] and result["stdout"].strip():
        return result["stdout"].strip()
    return None


def find_gstack_root() -> Path | None:
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


def gstack_bin() -> Path | None:
    root = find_gstack_root()
    if not root:
        return None
    candidate = root / "bin"
    return candidate if candidate.exists() else None


def project_slug(project_path: Path) -> str:
    digest = hashlib.sha256(str(project_path).encode("utf-8")).hexdigest()[:12]
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", project_path.name).strip("-") or "project"
    return f"{base}-{digest}"


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


DEFAULT_ENTERPRISE_POLICY: dict[str, Any] = {
    "schemaVersion": "gstack.enterprise.v1",
    "standard": "enterprise",
    "requiredChecks": [
        "project_instructions_read",
        "git_status_reviewed",
        "diff_check_clean",
        "test_commands_discovered",
        "focused_tests_run_or_blocked",
        "secret_scan_clean",
        "security_review_for_sensitive_work",
        "release_approval_for_production",
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


def parse_simple_yaml(text: str) -> dict[str, Any] | None:
    """Parse a conservative one-level YAML subset without external deps."""
    data: dict[str, Any] = {}
    current_key: str | None = None
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


def read_policy_file(path: Path) -> dict[str, Any] | None:
    if path.suffix.lower() == ".json":
        return read_json(path)
    if path.suffix.lower() in {".yml", ".yaml"}:
        try:
            return parse_simple_yaml(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
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


def policy_candidates(project_path: Path) -> list[Path]:
    return [
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
    for path in policy_candidates(project_path):
        if not path.exists():
            continue
        parsed = read_policy_file(path)
        if parsed is None:
            raise ToolError(f"Could not parse gstack policy file: {path}")
        policy = deep_merge(DEFAULT_ENTERPRISE_POLICY, parsed)
        policy["_sourcePath"] = str(path)
        policy["_usingDefault"] = False
        return policy
    policy = json.loads(json.dumps(DEFAULT_ENTERPRISE_POLICY))
    policy["_sourcePath"] = None
    policy["_usingDefault"] = True
    return policy


def git_changed_files(project_path: Path) -> list[str]:
    commands = [
        ["git", "diff", "--name-only"],
        ["git", "diff", "--cached", "--name-only"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ]
    seen: set[str] = set()
    files: list[str] = []
    for command in commands:
        result = safe_run(command, project_path, timeout=10)
        if not result["ok"]:
            continue
        for line in result["stdout"].splitlines():
            item = line.strip().replace("\\", "/")
            if item and item not in seen:
                seen.add(item)
                files.append(item)
    return files


def path_matches_patterns(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern.replace("\\", "/")) for pattern in patterns)


def goal_is_sensitive(goal: str, policy: dict[str, Any]) -> bool:
    goal_l = goal.lower()
    keywords = policy.get("security", {}).get("sensitiveKeywords") or []
    return any(str(keyword).lower() in goal_l for keyword in keywords)


def percentage_from_text(text: str, labels: list[str]) -> float | None:
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
            commands.append(
                {
                    "key": f"npm:{script_name}",
                    "label": f"npm run {script_name}" if script_name != "test" else "npm test",
                    "source": "package.json",
                    "script": scripts[script_name],
                    "args": ["npm", "test"] if script_name == "test" else ["npm", "run", script_name],
                }
            )
    if (project_path / "pytest.ini").exists() or (project_path / "pyproject.toml").exists() or (project_path / "tests").exists():
        commands.append(
            {
                "key": "python:pytest",
                "label": "python3 -m pytest",
                "source": "python project detection",
                "args": ["python3", "-m", "pytest"],
            }
        )
    if (project_path / "Cargo.toml").exists():
        commands.append({"key": "cargo:test", "label": "cargo test", "source": "Cargo.toml", "args": ["cargo", "test"]})
    if (project_path / "go.mod").exists():
        commands.append({"key": "go:test", "label": "go test ./...", "source": "go.mod", "args": ["go", "test", "./..."]})
    return commands


def skill_files() -> list[Path]:
    root = find_gstack_root()
    if not root:
        return []
    files = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if child.name in EXCLUDED_DIRS or child.name == "node_modules":
            continue
        skill_file = child / "SKILL.md"
        if skill_file.exists():
            files.append(skill_file)
    root_skill = root / "SKILL.md"
    if root_skill.exists():
        files.insert(0, root_skill)
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


def workflow_skill_names() -> list[str]:
    names: list[str] = []
    for group in WORKFLOW_PROFILE:
        for skill in group["skills"]:
            if skill not in names:
                names.append(skill)
    return names


def roster_agent(agent_id: str) -> dict[str, Any]:
    return next(agent for agent in AGENT_ROSTER if agent["id"] == agent_id)


def choose_agent_team(goal: str, classifications: list[dict[str, Any]], quality_level: str = "enterprise") -> dict[str, Any]:
    classification_ids = {item["id"] for item in classifications}
    goal_l = goal.lower()
    selected_ids: list[str] = ["lead"]

    def add(agent_id: str) -> None:
        if agent_id not in selected_ids:
            selected_ids.append(agent_id)

    if "trivial" in classification_ids and quality_level == "standard":
        return {
            "mode": "single-agent",
            "reason": "Trivial or standard-quality task; use the Lead Engineer only unless new risk appears.",
            "maxAgents": 1,
            "specialistCount": 0,
            "requiresLeadJustification": False,
            "agents": [roster_agent("lead")],
            "dispatchPolicy": TEAM_DISPATCH_POLICY,
            "handoffContract": team_handoff_contract(["lead"]),
            "blockedActions": team_blocked_actions(),
        }

    if "normal" in classification_ids:
        add("investigator")
        add("reviewer")
    if "architecture" in classification_ids:
        add("architect")
        add("investigator")
        add("reviewer")
        add("docs")
    if "product" in classification_ids:
        add("product")
        add("docs")
    if "ui_product" in classification_ids:
        add("product")
        add("qa")
        add("reviewer")
    if "security_compliance" in classification_ids:
        add("security")
        add("reviewer")
    if "data_financial" in classification_ids:
        add("quant")
        add("reviewer")
    if "production_release" in classification_ids:
        add("security")
        add("devops")
        add("qa")
        add("reviewer")
        add("docs")
    if re.search(r"debug|root cause|failing|broken|crash|regression", goal_l):
        add("investigator")
        add("qa")
    if re.search(r"implement|build|code|create|scaffold", goal_l):
        add("builder")
        add("reviewer")
    if re.search(r"readme|docs|documentation|github repo|repository|package", goal_l):
        add("docs")
    if quality_level == "enterprise" and len(selected_ids) == 1:
        add("reviewer")

    agents = [roster_agent(agent_id) for agent_id in selected_ids]
    mode = "single-agent" if selected_ids == ["lead"] else "lead-plus-specialists"
    specialist_count = max(0, len(selected_ids) - 1)
    return {
        "mode": mode,
        "reason": "Team selected from task risk classes and enterprise quality level.",
        "maxAgents": 1 + int(TEAM_DISPATCH_POLICY["defaultMaxSpecialists"]),
        "specialistCount": specialist_count,
        "requiresLeadJustification": specialist_count > int(TEAM_DISPATCH_POLICY["defaultMaxSpecialists"]),
        "agents": agents,
        "dispatchPolicy": TEAM_DISPATCH_POLICY,
        "handoffContract": team_handoff_contract(selected_ids),
        "blockedActions": team_blocked_actions(),
    }


def team_handoff_contract(agent_ids: list[str]) -> dict[str, Any]:
    return {
        "leadMustSynthesize": True,
        "requiredFromEachSpecialist": [
            "scope handled",
            "evidence gathered",
            "findings or changes",
            "blockers",
            "residual risk",
        ],
        "writeOwnership": "Any editing specialist must own a disjoint file/module scope and list changed paths.",
        "finalLeadChecklist": [
            "specialist results reconciled",
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
        "Subagents must not deploy, push, merge, delete data, reset git state, restart production, alter DNS/SSL, or modify production systems.",
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


def mastery_stage(stage_number: int) -> dict[str, Any]:
    return next(stage for stage in MASTERY_STAGES if stage["stage"] == stage_number)


def choose_mastery_stage(goal: str, classifications: list[dict[str, Any]]) -> int:
    goal_l = goal.lower()
    if re.search(r"debug|root cause|repro|broken|failing|failure", goal_l):
        return 3
    stages = [STAGE_BY_CLASSIFICATION.get(item["id"], 2) for item in classifications]
    return max(stages) if stages else 2


def task_anti_slop_checklist(classifications: list[dict[str, Any]]) -> list[str]:
    checklist = list(ANTI_SLOP_BASE)
    for classification in classifications:
        for item in ANTI_SLOP_BY_CLASSIFICATION.get(classification["id"], []):
            if item not in checklist:
                checklist.append(item)
    return checklist


def build_task_training(goal: str, classifications: list[dict[str, Any]], required_gates: list[str]) -> dict[str, Any]:
    stage_number = choose_mastery_stage(goal, classifications)
    stage = mastery_stage(stage_number)
    guidance = STAGE_TRAINING[stage_number]
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
    }


def mastery_system() -> dict[str, Any]:
    return {
        "standard": "Enterprise professional development: evidence-driven, source-backed, production-safe, and designed to train Jay from operator fundamentals to staff-level execution.",
        "stages": MASTERY_STAGES,
        "operatorScoreScale": OPERATOR_SCORE_SCALE,
        "antiSlopBase": ANTI_SLOP_BASE,
    }


def tool_detect_project(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    g_root = find_gstack_root()
    bin_dir = gstack_bin()
    project_config_paths = [
        project_path / ".gstack" / "project.yaml",
        project_path / ".gstack" / "project.yml",
        project_path / ".gstack" / "project.json",
        project_path / "gstack.yaml",
        project_path / "gstack.yml",
    ]
    project_config = [str(path) for path in project_config_paths if path.exists()]
    return {
        "projectPath": str(project_path),
        "gitRoot": git_root(project_path),
        "gstackRoot": str(g_root) if g_root else None,
        "gstackBin": str(bin_dir) if bin_dir else None,
        "gstackInstalled": bool(g_root),
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
    raise ToolError(f"Unknown gstack skill: {skill_name}. Use gstack_list_skills first.")


def tool_plan(args: dict[str, Any]) -> dict[str, Any]:
    goal = str(args.get("goal") or "").strip()
    if not goal:
        raise ToolError("goal is required.")
    project_path = require_project_path(args.get("project_path"))
    quality_level = str(args.get("quality_level") or "enterprise").strip().lower()
    if quality_level not in {"standard", "enterprise"}:
        raise ToolError("quality_level must be 'standard' or 'enterprise'.")
    mastery_mode = bool(args.get("mastery_mode", True))
    classifications = classify_work(goal)
    selected = choose_skills(goal, quality_level=quality_level)
    team_plan = choose_agent_team(goal, classifications, quality_level=quality_level)
    detected = tool_detect_project({"project_path": str(project_path)})
    steps = [
        {
            "gate": "Classify",
            "skill": "gstack_plan",
            "purpose": "Classify the work by risk and select the strictest matching workflow.",
            "doneWhen": "The plan names the applicable risk classes and required gates.",
        },
        {
            "gate": "Context",
            "skill": "gstack_detect_project -> context-restore",
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
            "skill": "gstack_health -> gstack_review -> investigate -> gstack_qa",
            "purpose": "Check repo health, review diffs, run focused verification, and investigate root causes for defects.",
            "doneWhen": "Relevant lint/typecheck/test/build checks pass or failures are clearly reported.",
        },
        {
            "gate": "Security/compliance",
            "skill": "gstack_security_audit -> cso",
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
            "skill": "gstack_ship_check -> ship -> land-and-deploy -> canary",
            "purpose": "Prepare, release, deploy, and monitor only when the user explicitly asks for release/deploy work.",
            "doneWhen": "Release work has explicit approval and ship/deploy/canary checks are complete.",
        },
        {
            "gate": "Handoff",
            "skill": "gstack_context_save -> document-release -> learn",
            "purpose": "Save decisions, files changed, checks run, risks, open items, and durable memory.",
            "doneWhen": "The handoff states what changed, what was checked, remaining risk, and next steps.",
        },
    ]
    release_blockers: list[str] = []
    required_gates: list[str] = []
    for classification in classifications:
        for blocker in classification.get("releaseBlockers", []):
            if blocker not in release_blockers:
                release_blockers.append(blocker)
        for gate in classification.get("requiredGates", []):
            if gate not in required_gates:
                required_gates.append(gate)
    task_training = build_task_training(goal, classifications, required_gates) if mastery_mode else None
    return {
        "goal": goal,
        "qualityLevel": quality_level,
        "masteryMode": mastery_mode,
        "classifications": classifications,
        "project": detected,
        "workflowProfile": WORKFLOW_PROFILE,
        "masterySystem": mastery_system(),
        "taskTraining": task_training,
        "agentTeam": team_plan,
        "antiSlopChecklist": task_training["antiSlopChecklist"] if task_training else ANTI_SLOP_BASE,
        "recommendedSkills": selected,
        "availableWorkflowSkills": workflow_skill_names(),
        "requiredGates": required_gates,
        "releaseBlockers": release_blockers,
        "plan": steps,
        "policy": {
            "intent": "Use gstack as an enterprise workflow router and quality gate.",
            "noArbitraryShell": "Do not execute arbitrary shell commands through this MCP.",
            "approvalBoundary": "Do not deploy, push, merge, delete data, reset git state, restart production, alter DNS/SSL, or modify production systems unless explicitly requested and allowed by project rules.",
            "productionBar": "Do not call work production-ready if required tests, security, QA, or docs for the risk class are missing.",
            "antiSlopStandard": "No fake data, fake test results, hidden assumptions, unverifiable completion claims, unrelated churn, or unapproved production mutation.",
            "masteryStandard": "For non-trivial work, include the skill stage, learning objective, expert mental model, benchmarks, review rubric, and next drill.",
        },
    }


def tool_team_plan(args: dict[str, Any]) -> dict[str, Any]:
    goal = str(args.get("goal") or "").strip()
    if not goal:
        raise ToolError("goal is required.")
    quality_level = str(args.get("quality_level") or "enterprise").strip().lower()
    if quality_level not in {"standard", "enterprise"}:
        raise ToolError("quality_level must be 'standard' or 'enterprise'.")
    classifications = classify_work(goal)
    return {
        "goal": goal,
        "qualityLevel": quality_level,
        "classifications": classifications,
        "team": choose_agent_team(goal, classifications, quality_level=quality_level),
        "availableRoster": AGENT_ROSTER,
        "policy": TEAM_DISPATCH_POLICY,
    }


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
    return {
        "id": agent_id,
        "readOnly": read_only,
        "mayEdit": not read_only,
        "writeScope": [str(item).replace("\\", "/") for item in write_scope],
        "task": str(agent.get("task") or ""),
    }


def tool_dispatch_check(args: dict[str, Any]) -> dict[str, Any]:
    goal = str(args.get("goal") or "").strip()
    proposed = args.get("team") or args.get("agents") or {}
    if isinstance(proposed, dict):
        raw_agents = proposed.get("agents") or []
    elif isinstance(proposed, list):
        raw_agents = proposed
    else:
        raw_agents = []
    agents = [normalize_agent_plan(agent) for agent in raw_agents]
    agents = [agent for agent in agents if agent.get("id")]
    max_specialists = int(args.get("max_specialists") or TEAM_DISPATCH_POLICY["defaultMaxSpecialists"])
    explicit_justification = str(args.get("lead_justification") or "").strip()
    explicit_release_requested = bool(args.get("explicit_release_requested") or False)
    classifications = classify_work(goal) if goal else []
    classification_ids = {item["id"] for item in classifications}
    blockers: list[str] = []
    warnings: list[str] = []

    ids = [agent["id"] for agent in agents]
    if "lead" not in ids:
        blockers.append("Agent plan must include the Lead Engineer with id 'lead'.")
    duplicates = sorted({agent_id for agent_id in ids if ids.count(agent_id) > 1})
    if duplicates:
        blockers.append("Duplicate agent ids are not allowed: " + ", ".join(duplicates))
    specialist_count = len([agent for agent in agents if agent["id"] != "lead"])
    if specialist_count > max_specialists and not explicit_justification:
        blockers.append(f"Agent plan has {specialist_count} specialists; default maximum is {max_specialists} without lead justification.")
    if "production_release" in classification_ids and not explicit_release_requested:
        blockers.append("Production/release-classified work requires explicit release approval before deploy/release actions.")

    write_owners: dict[str, str] = {}
    for agent in agents:
        if not agent["mayEdit"]:
            continue
        if agent["id"] != "lead" and not agent["writeScope"]:
            warnings.append(f"Editing specialist '{agent['id']}' has no explicit write scope.")
        for scope in agent["writeScope"]:
            if scope in write_owners:
                blockers.append(f"Write-scope overlap: '{scope}' owned by both {write_owners[scope]} and {agent['id']}.")
            write_owners[scope] = agent["id"]
    for agent in agents:
        if agent["id"] != "lead" and re.search(r"\bspawn\b|\bdelegate\b|\bsubagent\b", agent["task"], re.IGNORECASE):
            blockers.append(f"Subagent '{agent['id']}' task appears to delegate/spawn; only the Lead Engineer may orchestrate.")

    return {
        "goal": goal,
        "valid": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "classifications": classifications,
        "specialistCount": specialist_count,
        "maxSpecialists": max_specialists,
        "leadJustification": explicit_justification,
        "agents": agents,
        "blockedActions": team_blocked_actions(),
        "policy": TEAM_DISPATCH_POLICY,
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
    return {
        "projectPath": str(project_path),
        "status": safe_run(["git", "status", "--short"], project_path, timeout=10),
        "diffStat": safe_run(["git", "diff", "--stat"], project_path, timeout=15),
        "diffCheck": safe_run(["git", "diff", "--check"], project_path, timeout=15),
        "changedFiles": safe_run(["git", "diff", "--name-only"], project_path, timeout=15),
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
    if path.name.startswith(".") and path.name not in {".env", ".env.example"}:
        return False
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tar", ".sqlite", ".db"}:
        return False
    try:
        return path.stat().st_size <= 1_000_000
    except OSError:
        return False


def tool_security_audit(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    max_files = int(args.get("max_files") or 2000)
    findings: list[dict[str, Any]] = []
    scanned = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [item for item in dirs if item not in EXCLUDED_DIRS]
        for filename in files:
            if scanned >= max_files:
                break
            path = Path(root) / filename
            if not should_scan(path):
                continue
            scanned += 1
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                for name, pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            {
                                "file": str(path.relative_to(project_path)),
                                "line": line_no,
                                "pattern": name,
                                "preview": truncate(pattern.sub("[REDACTED]", line.strip()), 240),
                            }
                        )
                        break
                if len(findings) >= 100:
                    break
            if len(findings) >= 100:
                break
        if scanned >= max_files or len(findings) >= 100:
            break
    return {
        "projectPath": str(project_path),
        "scannedFiles": scanned,
        "truncated": scanned >= max_files or len(findings) >= 100,
        "findingCount": len(findings),
        "findings": findings,
        "note": "Heuristic local scan only. Use formal secret scanning and dependency/container scanning before production release.",
    }


def tool_qa(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    commands = discover_test_commands(project_path)
    run = bool(args.get("run") or False)
    command_key = str(args.get("command_key") or "").strip()
    result: dict[str, Any] | None = None
    if run:
        if not command_key:
            raise ToolError("When run=true, command_key is required. Use gstack_qa with run=false to list allowed keys.")
        selected = next((command for command in commands if command["key"] == command_key), None)
        if not selected:
            raise ToolError(f"Unsupported command_key: {command_key}. Allowed: {[command['key'] for command in commands]}")
        result = safe_run(selected["args"], project_path, timeout=int(args.get("timeout_sec") or 120))
    return {
        "projectPath": str(project_path),
        "allowedCommands": commands,
        "executed": result is not None,
        "result": result,
        "policy": "Only discovered test/build commands can be executed. No arbitrary shell is exposed.",
    }


def context_dir(project_path: Path) -> Path:
    return Path.home() / ".gstack" / "mcp-context" / project_slug(project_path)


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
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    save_path = target_dir / f"{timestamp}.json"
    latest_path = target_dir / "latest.json"
    save_path.write_text(json_text(payload) + "\n", encoding="utf-8")
    latest_path.write_text(json_text(payload) + "\n", encoding="utf-8")
    return {"saved": True, "path": str(save_path), "latestPath": str(latest_path), "context": payload}


def tool_context_restore(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    latest_path = context_dir(project_path) / "latest.json"
    if not latest_path.exists():
        raise ToolError(f"No saved gstack MCP context for {project_path}")
    data = read_json(latest_path)
    if data is None:
        raise ToolError(f"Saved context is not valid JSON: {latest_path}")
    return {"restored": True, "path": str(latest_path), "context": data}


def tool_ship_check(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    health = tool_health({"project_path": str(project_path)})
    review = tool_review({"project_path": str(project_path)})
    docs = health["projectFiles"]
    blockers = []
    if review["diffCheck"]["returncode"] not in (0,):
        blockers.append("git diff --check reported whitespace or conflict-marker issues")
    if not docs.get("readme"):
        blockers.append("README is missing")
    if not health["testCommands"]:
        blockers.append("No test commands detected")
    return {
        "projectPath": str(project_path),
        "ready": not blockers,
        "blockers": blockers,
        "healthSummary": {
            "branch": health["branch"],
            "dirtyFileCount": health["dirtyFileCount"],
            "testCommandCount": len(health["testCommands"]),
            "docs": docs,
        },
        "recommendedGate": [
            "Run focused tests for touched code.",
            "Run security scan for auth, secrets and external integration changes.",
            "Review diff before deploy.",
            "Save context after deployment or handoff.",
        ],
    }


def tool_policy_check(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    goal = str(args.get("goal") or "").strip()
    explicit_release_requested = bool(args.get("explicit_release_requested") or False)
    target_environment = str(args.get("target_environment") or "local").strip().lower()
    policy = load_enterprise_policy(project_path)
    changed_files = git_changed_files(project_path)
    protected_patterns = [str(item) for item in policy.get("protectedPaths", [])]
    protected_matches = [path for path in changed_files if path_matches_patterns(path, protected_patterns)]
    classifications = classify_work(goal) if goal else []
    classification_ids = {item["id"] for item in classifications}
    blockers: list[str] = []
    warnings: list[str] = []
    required_actions: list[str] = []

    if policy.get("_usingDefault"):
        warnings.append("No project gstack policy file found; using default enterprise policy.")
        required_actions.append("Add a project policy file such as gstack.enterprise.json or gstack.yml before treating the repo as production-governed.")
    if protected_matches:
        blockers.append("Protected paths changed without an explicit project-specific approval record.")
    if target_environment in {"production", "prod"} and not explicit_release_requested:
        blockers.append("Production target selected but explicit release approval was not provided.")
    if "production-release-deploy" in classification_ids and not explicit_release_requested:
        blockers.append("Release/deploy-classified work requires explicit release approval.")
    if goal and goal_is_sensitive(goal, policy):
        required_actions.append("Run gstack_security_audit and perform a human security/compliance review before release.")
    if "data-financial-integration-sensitive" in classification_ids:
        required_actions.append("Document data source, contract assumptions, failure modes, and reconciliation/rollback path.")
    if "ui-product-sensitive" in classification_ids:
        required_actions.append("Capture browser/visual QA evidence for changed user-facing flows.")

    return {
        "projectPath": str(project_path),
        "policySource": policy.get("_sourcePath"),
        "usingDefaultPolicy": bool(policy.get("_usingDefault")),
        "targetEnvironment": target_environment,
        "explicitReleaseRequested": explicit_release_requested,
        "classifications": classifications,
        "changedFiles": changed_files,
        "protectedPatterns": protected_patterns,
        "protectedMatches": protected_matches,
        "requiredChecks": policy.get("requiredChecks", []),
        "requiredActions": required_actions,
        "blockers": blockers,
        "warnings": warnings,
        "policy": {key: value for key, value in policy.items() if not key.startswith("_")},
    }


def tool_preflight(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    goal = str(args.get("goal") or "").strip()
    strict = bool(args.get("strict", True))
    run_secret_scan = bool(args.get("run_secret_scan", True))
    policy_check = tool_policy_check(args)
    health = tool_health({"project_path": str(project_path)})
    review = tool_review({"project_path": str(project_path)})
    blockers = list(policy_check["blockers"])
    warnings = list(policy_check["warnings"])

    if strict and policy_check["usingDefaultPolicy"]:
        blockers.append("Strict preflight requires a project gstack policy file.")
    if review["diffCheck"]["returncode"] != 0:
        blockers.append("git diff --check reported whitespace, conflict-marker, or patch hygiene issues.")
    if not health["testCommands"]:
        blockers.append("No test/build commands were discovered; define project checks or document why none exist.")
    if health["dirtyFileCount"] and not goal:
        warnings.append("Working tree has changes and no task goal was provided for risk classification.")

    security: dict[str, Any] | None = None
    if run_secret_scan:
        security = tool_security_audit({"project_path": str(project_path), "max_files": int(args.get("max_files") or 2000)})
        if security["findingCount"] > 0:
            blockers.append("Secret/security scan found possible credentials or sensitive values.")

    required_evidence = [
        "Project instructions reviewed",
        "Risk class selected",
        "Changed files reviewed",
        "Protected paths checked",
        "Diff hygiene checked",
        "Test/build commands discovered",
        "Secret scan reviewed",
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


def tool_release_readiness(args: dict[str, Any]) -> dict[str, Any]:
    project_path = require_project_path(args.get("project_path"))
    target_environment = str(args.get("target_environment") or "production").strip().lower()
    explicit_release_requested = bool(args.get("explicit_release_requested") or False)
    rollback_plan = str(args.get("rollback_plan") or "").strip()
    monitoring_plan = str(args.get("monitoring_plan") or "").strip()
    canary_plan = str(args.get("canary_plan") or "").strip()
    approved_by = str(args.get("approved_by") or "").strip()
    preflight_args = dict(args)
    preflight_args["strict"] = True
    preflight_args["target_environment"] = target_environment
    preflight_args["explicit_release_requested"] = explicit_release_requested
    preflight = tool_preflight(preflight_args)
    ship = tool_ship_check({"project_path": str(project_path)})
    blockers = list(preflight["blockers"]) + list(ship["blockers"])
    warnings = list(preflight["warnings"])

    if not explicit_release_requested:
        blockers.append("Release readiness requires explicit user approval for this release check.")
    if target_environment in {"production", "prod"} and not approved_by:
        blockers.append("Production release requires an approver name or approval reference.")
    if target_environment in {"production", "prod"} and not rollback_plan:
        blockers.append("Production release requires a rollback plan.")
    if target_environment in {"production", "prod"} and not (monitoring_plan or canary_plan):
        blockers.append("Production release requires a monitoring or canary plan.")

    return {
        "projectPath": str(project_path),
        "targetEnvironment": target_environment,
        "ready": not blockers,
        "blockers": list(dict.fromkeys(blockers)),
        "warnings": warnings,
        "approval": {
            "explicitReleaseRequested": explicit_release_requested,
            "approvedBy": approved_by,
        },
        "plans": {
            "rollbackPlan": rollback_plan,
            "monitoringPlan": monitoring_plan,
            "canaryPlan": canary_plan,
        },
        "preflight": preflight,
        "shipCheck": ship,
        "releaseStandard": [
            "No unresolved blockers.",
            "Tests and security checks are evidenced or explicitly blocked.",
            "Rollback and monitoring are documented before production.",
            "Production mutation is approved by the user and allowed by project rules.",
        ],
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
    report_metrics: dict[str, Any] | None = None
    warnings: list[str] = []
    blockers: list[str] = []
    if report_path_raw:
        report_path = Path(report_path_raw).expanduser()
        if not report_path.is_absolute():
            report_path = project_path / report_path
        if not report_path.exists():
            blockers.append(f"Backtest report path does not exist: {report_path}")
        else:
            report_metrics = parse_backtest_report(report_path)
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
        if not any(evidence.get(alias) not in (None, "", False, []) for alias in aliases):
            missing.append(item)
    if missing:
        blockers.append("Missing required quant/backtest evidence: " + ", ".join(missing))

    min_quality = float(quant_policy.get("minimumHistoryQualityPercent") or 99.0)
    supplied_quality = evidence.get("history_quality") or evidence.get("modelling_quality") or evidence.get("modeling_quality")
    detected_quality = report_metrics.get("historyQualityPercent") if report_metrics else None
    quality_value = supplied_quality if supplied_quality is not None else detected_quality
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


TOOLS: dict[str, dict[str, Any]] = {
    "gstack_detect_project": {
        "description": "Detect git root, gstack install, project config and test commands for a project path.",
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
        "description": "Create a gstack-oriented execution and mastery plan for a project goal using installed skills, safe quality gates, anti-slop standards, and skill benchmarks.",
        "inputSchema": {
            "type": "object",
            "required": ["goal"],
            "properties": {
                "goal": {"type": "string"},
                "project_path": {"type": "string"},
                "quality_level": {"type": "string", "enum": ["standard", "enterprise"], "default": "enterprise"},
                "mastery_mode": {"type": "boolean", "default": True, "description": "When true, include staged training objectives, benchmarks, anti-slop checklist, review rubric, and next drill."},
            },
        },
        "handler": tool_plan,
        "readOnlyHint": True,
    },
    "gstack_team_plan": {
        "description": "Create a lead-agent plus specialist-team dispatch plan for a goal, including roles, evidence requirements, and anti-swarm safety rules.",
        "inputSchema": {
            "type": "object",
            "required": ["goal"],
            "properties": {
                "goal": {"type": "string"},
                "quality_level": {"type": "string", "enum": ["standard", "enterprise"], "default": "enterprise"},
            },
        },
        "handler": tool_team_plan,
        "readOnlyHint": True,
    },
    "gstack_dispatch_check": {
        "description": "Validate a proposed multi-agent dispatch plan for lead accountability, max specialist count, write-scope overlap, and blocked actions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "goal": {"type": "string"},
                "team": {"type": "object", "description": "Object containing an agents array, usually from gstack_team_plan."},
                "agents": {"type": "array", "items": {"type": "object"}, "description": "Alternative direct agent list."},
                "max_specialists": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
                "lead_justification": {"type": "string"},
                "explicit_release_requested": {"type": "boolean", "default": False},
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
                "goal": {"type": "string"},
                "target_environment": {"type": "string", "default": "local"},
                "explicit_release_requested": {"type": "boolean", "default": False},
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
                "goal": {"type": "string"},
                "target_environment": {"type": "string", "default": "local"},
                "explicit_release_requested": {"type": "boolean", "default": False},
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
        "inputSchema": {"type": "object", "properties": {"project_path": {"type": "string"}}},
        "handler": tool_health,
        "readOnlyHint": True,
    },
    "gstack_review": {
        "description": "Run safe local review checks: git status, diff stat, changed files and git diff --check.",
        "inputSchema": {"type": "object", "properties": {"project_path": {"type": "string"}}},
        "handler": tool_review,
        "readOnlyHint": True,
    },
    "gstack_security_audit": {
        "description": "Run a bounded local heuristic secret/security scan with common credential patterns and production caveats.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "max_files": {"type": "integer", "minimum": 100, "maximum": 10000, "default": 2000},
            },
        },
        "handler": tool_security_audit,
        "readOnlyHint": True,
    },
    "gstack_qa": {
        "description": "Discover allowed test/build commands, and optionally run one discovered command by key. No arbitrary shell is exposed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "run": {"type": "boolean", "default": False},
                "command_key": {"type": "string", "description": "Required only when run=true. Use output allowedCommands keys."},
                "timeout_sec": {"type": "integer", "minimum": 10, "maximum": 600, "default": 120},
            },
        },
        "handler": tool_qa,
        "readOnlyHint": False,
    },
    "gstack_context_save": {
        "description": "Save a concise project handoff context under ~/.gstack/mcp-context for future restoration.",
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
        "inputSchema": {"type": "object", "properties": {"project_path": {"type": "string"}}},
        "handler": tool_ship_check,
        "readOnlyHint": True,
    },
    "gstack_release_readiness": {
        "description": "Run production-style release readiness: strict preflight, ship check, explicit approval, rollback, monitoring and canary evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "goal": {"type": "string"},
                "target_environment": {"type": "string", "default": "production"},
                "explicit_release_requested": {"type": "boolean", "default": False},
                "approved_by": {"type": "string"},
                "rollback_plan": {"type": "string"},
                "monitoring_plan": {"type": "string"},
                "canary_plan": {"type": "string"},
                "run_secret_scan": {"type": "boolean", "default": True},
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


def tool_definitions() -> list[dict[str, Any]]:
    definitions = []
    for name, meta in TOOLS.items():
        definitions.append(
            {
                "name": name,
                "description": meta["description"],
                "inputSchema": meta["inputSchema"],
                "annotations": {
                    "readOnlyHint": bool(meta.get("readOnlyHint", True)),
                    "destructiveHint": False,
                    "openWorldHint": False,
                },
            }
        )
    return definitions


def mcp_result(data: Any) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json_text(data)}],
        "structuredContent": data,
    }


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    try:
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }
        if method == "notifications/initialized":
            return None
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tool_definitions()}}
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if name not in TOOLS:
                raise ToolError(f"Unknown tool: {name}")
            if not isinstance(arguments, dict):
                raise ToolError("Tool arguments must be an object.")
            data = TOOLS[name]["handler"](arguments)
            return {"jsonrpc": "2.0", "id": request_id, "result": mcp_result(data)}
        if request_id is None:
            return None
        raise ToolError(f"Unsupported MCP method: {method}")
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


def read_message() -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("ascii", errors="replace").strip()
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.lower()] = value.strip()
    length_raw = headers.get("content-length")
    if not length_raw:
        return None
    body = sys.stdin.buffer.read(int(length_raw))
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def main() -> int:
    while True:
        message = read_message()
        if message is None:
            return 0
        response = handle_request(message)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    raise SystemExit(main())
