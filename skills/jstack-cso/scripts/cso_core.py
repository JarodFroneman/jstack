"""Read-only deterministic evidence collection for JStack CSO."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping, Optional, Union


EVIDENCE_SCHEMA_VERSION = "1.0.0"
REPORT_SCHEMA_VERSION = "2.1.0"

DEFAULT_LIMITS = {
    "maxFiles": 5_000,
    "maxFileBytes": 2 * 1024 * 1024,
    "maxTotalBytes": 50 * 1024 * 1024,
}

MAX_LIMITS = {
    "maxFiles": 25_000,
    "maxFileBytes": 10 * 1024 * 1024,
    "maxTotalBytes": 250 * 1024 * 1024,
}

MAX_EVIDENCE_ITEMS = 20_000
MAX_SUSPICIOUS_INSTRUCTIONS = 5_000

SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "Pods",
    "DerivedData",
    "coverage",
    ".cache",
    ".turbo",
    "__pycache__",
}

TEXT_EXTENSIONS = {
    ".astro", ".bat", ".c", ".cc", ".cer", ".cfg", ".cjs", ".cmd",
    ".conf", ".config", ".cpp", ".crt", ".cs", ".css", ".cts", ".dart", ".ejs",
    ".env", ".erl", ".ex", ".exs", ".gql", ".gradle", ".graphql",
    ".graphqls", ".groovy", ".go", ".h", ".hbs", ".hcl", ".hpp", ".hrl",
    ".htm", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".key",
    ".kt", ".kts", ".lock", ".lua", ".map", ".md", ".mjs", ".mod",
    ".mq4", ".mq5", ".mqh", ".mts", ".njk", ".pem", ".php", ".pine",
    ".pl", ".pm", ".properties", ".proto",
    ".ps1", ".py", ".rb", ".rs", ".scala", ".scss", ".sh", ".sql",
    ".sum", ".svelte", ".swift", ".tf", ".tfvars", ".toml", ".ts", ".tsx",
    ".txt", ".vue", ".xml", ".yaml", ".yml",
}

LANGUAGE_BY_EXTENSION = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".cjs": "JavaScript",
    ".mjs": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".mq4": "MQL",
    ".mq5": "MQL",
    ".mqh": "MQL",
    ".php": "PHP",
    ".pine": "Pine Script",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".swift": "Swift",
    ".tf": "Terraform HCL",
    ".tfvars": "Terraform HCL",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".cts": "TypeScript",
    ".mts": "TypeScript",
}

ENTERPRISE_MODULES = {
    "client-exposure",
    "secret-scanning",
    "api-minimization",
    "authorization",
    "business-logic",
    "reverse-engineering",
    "ai-security",
    "browser-security",
    "abuse-detection",
    "scanner-self-protection",
}

EXPOSURE_CLASSIFICATIONS = {
    "required-public-data",
    "authorized-user-data",
    "sensitive-data",
    "secret",
    "proprietary-logic",
    "debug-information",
    "unnecessary-metadata",
    "unknown",
}

EVIDENCE_DISPOSITIONS = {
    "verified-exposure",
    "candidate-finding",
    "control-present",
    "coverage-gap",
    "informational",
}

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

COVERAGE_GAP_REASONS = {
    "file-limit",
    "file-too-large",
    "total-byte-limit",
    "evidence-limit",
    "binary",
    "symlink",
    "read-error",
    "unsupported-format",
    "artifact-not-present",
}

BUILD_PATH = re.compile(
    r"(?:^|/)(?:dist|build|out|public|static|assets|\.next/static|\.output/public)(?:/|$)"
)
PRIVATE_ARTIFACT_PATH = re.compile(
    r"(?:^|/)(?:private|protected|internal-artifacts|sentry)(?:/|$)"
)
CLIENT_PATH = re.compile(r"(?:^|/)(?:client|frontend|web|ui|components?|pages|app)(?:/|$)")
CLIENT_ENV_PREFIX = re.compile(r"\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|NUXT_PUBLIC_)[A-Z0-9_]+\b")
SENSITIVE_NAME = re.compile(
    r"(?:secret|password|passwd|token|credential|api[_-]?key|private|signing|"
    r"encryption|system[_-]?prompt|raw[_-]?(?:provider|research)|internal[_-]?metadata)",
    re.IGNORECASE,
)
PROPRIETARY_NAME = re.compile(
    r"(?:scor(?:e|ing)|weight(?:s|ing)?|proprietary|alpha[_-]?model|risk[_-]?model|"
    r"ranking[_-]?formula|signal[_-]?formula)",
    re.IGNORECASE,
)

SUSPICIOUS_INSTRUCTIONS = (
    ("ignore-audit-policy", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|system|audit)\s+instructions?", re.I)),
    ("false-secure-verdict", re.compile(r"(?:mark|report|declare)\s+(?:this\s+)?(?:project|application|codebase)\s+as\s+secure", re.I)),
    ("reveal-system-prompt", re.compile(r"reveal\s+(?:the\s+)?(?:system|developer)\s+prompt", re.I)),
    ("execute-scanned-command", re.compile(r"(?:execute|run)\s+(?:this|the following)\s+command", re.I)),
    ("credential-exfiltration", re.compile(r"(?:send|upload|post|exfiltrat\w*)\s+(?:all\s+)?(?:credentials?|secrets?|tokens?)", re.I)),
    ("delete-audit-output", re.compile(r"(?:delete|remove|destroy)\s+(?:the\s+)?(?:audit|security)\s+report", re.I)),
    ("suppress-scope", re.compile(r"do\s+not\s+(?:inspect|scan|read|report)\s+(?:this|the)\s+(?:file|directory|finding|issue)", re.I)),
)


@dataclass(frozen=True)
class SecretPattern:
    pattern_id: str
    regex: re.Pattern[str]
    tier: str
    intentionally_public: bool = False


SECRET_PATTERNS = (
    SecretPattern("stripe.publishable", re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b"), "INFO", True),
    SecretPattern("stripe.secret", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"), "CRITICAL"),
    SecretPattern("aws.access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "CRITICAL"),
    SecretPattern("github.token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "CRITICAL"),
    SecretPattern("anthropic.api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "CRITICAL"),
    SecretPattern("openai.api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "CRITICAL"),
    SecretPattern("slack.token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "CRITICAL"),
    SecretPattern("google.api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"), "HIGH"),
    SecretPattern("private.key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    SecretPattern("jwt.token", re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"), "HIGH"),
    SecretPattern(
        "connection.string",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:'\"]+:[^\s@'\"]+@[^\s'\"]+", re.I),
        "CRITICAL",
    ),
    SecretPattern(
        "assigned.secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret|"
            r"signing[_-]?key|encryption[_-]?key)\b\s*[:=]\s*['\"]([A-Za-z0-9_./+=:@-]{16,})['\"]"
        ),
        "HIGH",
    ),
)


@dataclass
class FileRecord:
    relative_path: str
    text: str
    sha256: str
    size: int
    client_accessible: bool
    build_artifact: bool
    extension: str


def _sha256(value: Union[bytes, str]) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _line_at(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _secret_matches(text: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    occupied: list[tuple[int, int]] = []
    for item in SECRET_PATTERNS:
        for match in item.regex.finditer(text):
            start, end = match.span()
            if any(start < prior_end and end > prior_start for prior_start, prior_end in occupied):
                continue
            occupied.append((start, end))
            matches.append(
                {
                    "patternId": item.pattern_id,
                    "tier": item.tier,
                    "intentionallyPublic": item.intentionally_public,
                    "start": start,
                    "end": end,
                    "line": _line_number(text, start),
                }
            )
    return sorted(matches, key=lambda item: (item["start"], item["end"]))


def redact_text(text: str) -> str:
    matches = _secret_matches(text)
    if not matches:
        return text
    chunks: list[str] = []
    cursor = 0
    for match in matches:
        chunks.append(text[cursor : match["start"]])
        chunks.append("[REDACTED:%s]" % match["patternId"])
        cursor = match["end"]
    chunks.append(text[cursor:])
    return "".join(chunks)


def _safe_preview(value: str) -> str:
    return re.sub(r"\s+", " ", redact_text(value)).strip()[:180]


def _is_text_candidate(name: str) -> bool:
    if name.startswith(".env"):
        return True
    if name.startswith("Dockerfile"):
        return True
    if name in {".dockerignore", ".gitconfig", ".npmrc", ".pypirc", ".yarnrc", ".netrc"}:
        return True
    if name in {
        "CMakeLists.txt", "CODEOWNERS", "Gemfile", "Makefile", "Pipfile",
        "Procfile", "Rakefile", "go.mod", "go.sum",
    }:
        return True
    return Path(name).suffix.lower() in TEXT_EXTENSIONS


def _is_build_artifact(relative_path: str) -> bool:
    return bool(BUILD_PATH.search(relative_path))


def _is_client_accessible(relative_path: str, text: str) -> bool:
    if _is_build_artifact(relative_path):
        return True
    if re.search(r"\.(?:html?|css|map)$", relative_path) and not PRIVATE_ARTIFACT_PATH.search(relative_path):
        return True
    return bool(
        CLIENT_PATH.search(relative_path)
        and (
            re.search(r"['\"]use client['\"]", text)
            or re.search(r"\b(?:window|document|localStorage|sessionStorage|navigator|indexedDB)\b", text)
            or re.search(r"\b(?:React|Vue|Svelte|Angular)\b", text)
        )
    )


def _classify_artifact(relative_path: str, text: str) -> str:
    if relative_path.endswith(".map"):
        return "source-map"
    if re.search(r"(?:service-worker|sw\.js)$", relative_path, re.I):
        return "service-worker"
    if re.search(r"manifest(?:\.webmanifest|\.json)$", relative_path, re.I):
        return "manifest"
    if re.search(r"\.html?$", relative_path):
        return "html"
    if relative_path.endswith(".css"):
        return "css"
    if relative_path.endswith(".json"):
        return "hydration-data" if re.search(r"__NEXT_DATA__|dehydrat|initialState", text, re.I) else "static-json"
    if re.search(r"\.(?:js|mjs|cjs)$", relative_path):
        return "javascript-bundle"
    return "client-source"


def _resolve_limits(overrides: Optional[Mapping[str, Any]]) -> dict[str, int]:
    limits: dict[str, Any] = dict(DEFAULT_LIMITS)
    if overrides:
        unknown = set(overrides) - set(DEFAULT_LIMITS)
        if unknown:
            raise ValueError("unknown limit field(s): %s" % ", ".join(sorted(unknown)))
        limits.update(overrides)
    for name, value in limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("%s must be a positive integer" % name)
        if value > MAX_LIMITS[name]:
            raise ValueError("%s must not exceed %d" % (name, MAX_LIMITS[name]))
    return {name: int(value) for name, value in limits.items()}


def _report_directory(relative_path: str) -> bool:
    return relative_path in {".jstack/security-reports", ".gstack/security-reports"}


def _collect_files(root: Path, limits: Mapping[str, int]) -> tuple[list[FileRecord], list[dict[str, str]]]:
    files: list[FileRecord] = []
    gaps: list[dict[str, str]] = []
    total_bytes = 0
    stopped = False
    no_follow = getattr(os, "O_NOFOLLOW", 0)

    def walk(directory: Path) -> None:
        nonlocal stopped, total_bytes
        if stopped:
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            relative = directory.relative_to(root).as_posix() if directory != root else "."
            gaps.append({"path": relative, "reason": "read-error", "detail": str(exc)})
            return
        for entry in entries:
            if stopped:
                return
            absolute = Path(entry.path)
            relative = absolute.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                gaps.append({"path": relative, "reason": "read-error", "detail": str(exc)})
                continue
            if stat.S_ISLNK(metadata.st_mode):
                gaps.append({"path": relative, "reason": "symlink", "detail": "Symlink skipped to preserve repository path confinement."})
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if not _report_directory(relative) and entry.name not in SKIPPED_DIRECTORIES:
                    walk(absolute)
                continue
            if not stat.S_ISREG(metadata.st_mode) or not _is_text_candidate(entry.name):
                continue
            if len(files) >= limits["maxFiles"]:
                gaps.append({"path": relative, "reason": "file-limit", "detail": "Stopped at %d text files." % limits["maxFiles"]})
                stopped = True
                return
            if metadata.st_size > limits["maxFileBytes"]:
                gaps.append({"path": relative, "reason": "file-too-large", "detail": "%d bytes exceeds %d." % (metadata.st_size, limits["maxFileBytes"])})
                continue
            if total_bytes + metadata.st_size > limits["maxTotalBytes"]:
                gaps.append({"path": relative, "reason": "total-byte-limit", "detail": "Stopped before exceeding %d bytes." % limits["maxTotalBytes"]})
                stopped = True
                return
            descriptor: Optional[int] = None
            try:
                descriptor = os.open(absolute, os.O_RDONLY | no_follow)
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    gaps.append({"path": relative, "reason": "unsupported-format", "detail": "Non-regular file skipped."})
                    continue
                data = b""
                while True:
                    chunk = os.read(descriptor, min(64 * 1024, limits["maxFileBytes"] + 1 - len(data)))
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > limits["maxFileBytes"]:
                        break
                if len(data) > limits["maxFileBytes"]:
                    gaps.append({"path": relative, "reason": "file-too-large", "detail": "File grew beyond the per-file limit during inspection."})
                    continue
                if b"\0" in data[:8192]:
                    gaps.append({"path": relative, "reason": "binary", "detail": "Binary content skipped."})
                    continue
                text = data.decode("utf-8", errors="replace")
                extension = Path(entry.name).suffix.lower()
                files.append(
                    FileRecord(
                        relative_path=relative,
                        text=text,
                        sha256=_sha256(data),
                        size=len(data),
                        client_accessible=_is_client_accessible(relative, text),
                        build_artifact=_is_build_artifact(relative),
                        extension=extension,
                    )
                )
                total_bytes += len(data)
            except OSError as exc:
                gaps.append({"path": relative, "reason": "read-error", "detail": str(exc)})
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    walk(root)
    return files, gaps


def _detect_stack(files: Iterable[FileRecord]) -> dict[str, list[str]]:
    languages: set[str] = set()
    frameworks: set[str] = set()
    for file in files:
        language = LANGUAGE_BY_EXTENSION.get(file.extension)
        if language:
            languages.add(language)
        if file.relative_path == "package.json":
            try:
                package = json.loads(file.text)
            except (TypeError, ValueError):
                package = {}
            dependencies = {}
            if isinstance(package, dict):
                for key in ("dependencies", "devDependencies"):
                    value = package.get(key)
                    if isinstance(value, dict):
                        dependencies.update(value)
            for dependency, framework in {
                "next": "Next.js",
                "react": "React",
                "express": "Express",
                "fastify": "Fastify",
                "hono": "Hono",
                "vue": "Vue",
                "svelte": "Svelte",
                "@angular/core": "Angular",
            }.items():
                if dependency in dependencies:
                    frameworks.add(framework)
        if file.relative_path in {"pyproject.toml", "requirements.txt"}:
            for marker, framework in (("django", "Django"), ("fastapi", "FastAPI"), ("flask", "Flask")):
                if marker in file.text.lower():
                    frameworks.add(framework)
    adapters = {"generic-static"}
    if frameworks & {"Next.js", "React", "Express", "Fastify", "Hono"}:
        adapters.add("javascript-typescript-web")
    return {
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "adapters": sorted(adapters),
    }


def _extract_response_properties(text: str) -> list[str]:
    properties: set[str] = set()
    pattern = re.compile(r"(?:\.json|\.send|Response\.json|NextResponse\.json)\s*\(\s*\{([\s\S]{0,5000}?)\}\s*\)")
    for match in pattern.finditer(text):
        for prop in re.finditer(r"(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?::|,|$)", match.group(1), re.M):
            properties.add(prop.group(1))
    return sorted(properties)


def _extract_client_properties(files: Iterable[FileRecord]) -> set[str]:
    properties: set[str] = set()
    pattern = re.compile(r"\b(?:data|result|payload|responseData|apiResponse)\??\.([A-Za-z_$][\w$]*)\b")
    for file in files:
        if file.client_accessible:
            properties.update(match.group(1) for match in pattern.finditer(file.text))
    return properties


def _endpoint_names(file: FileRecord) -> list[str]:
    endpoints = {
        match.group(1)
        for match in re.finditer(r"(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", file.text)
    }
    next_match = re.search(r"(?:^|/)(?:app|pages)/(api/.*?)/(?:route\.(?:ts|js)|index\.(?:ts|js))$", file.relative_path)
    if next_match:
        endpoints.add("/" + re.sub(r"/index$", "", next_match.group(1)))
    pages_match = re.search(r"(?:^|/)pages/(api/.*?)\.(?:ts|js)$", file.relative_path)
    if pages_match:
        endpoints.add("/" + pages_match.group(1))
    if not endpoints and re.search(r"(?:req|request|res|response|NextResponse|Response\.json)", file.text):
        endpoints.add("file:" + file.relative_path)
    return sorted(endpoints)


CLASSIFICATION_ORDER = (
    "required-public-data",
    "authorized-user-data",
    "unknown",
    "debug-information",
    "unnecessary-metadata",
    "proprietary-logic",
    "sensitive-data",
    "secret",
)


def _strongest_classification(current: str, candidate: str) -> str:
    return candidate if CLASSIFICATION_ORDER.index(candidate) > CLASSIFICATION_ORDER.index(current) else current


def _iso_datetime(value: Optional[datetime]) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def analyze_repository(
    root: Union[str, os.PathLike[str]],
    *,
    now: Optional[datetime] = None,
    limits: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    repository_root = Path(root).expanduser().resolve(strict=True)
    if not repository_root.is_dir():
        raise ValueError("root must be a directory")
    resolved_limits = _resolve_limits(limits)
    files, gaps = _collect_files(repository_root, resolved_limits)
    evidence: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    exposure_by_path: dict[str, dict[str, Any]] = {}
    limit_gaps: set[str] = set()

    def add_limit_gap(detail: str) -> None:
        if detail in limit_gaps:
            return
        limit_gaps.add(detail)
        gaps.append({"path": ".", "reason": "evidence-limit", "detail": detail})

    def add_evidence(
        *,
        module: str,
        kind: str,
        title: str,
        classification: str,
        disposition: str,
        severity: str,
        confidence: Union[int, float],
        file: FileRecord,
        line: int,
        verified_fact: str,
        inference: Optional[str] = None,
        preview: Optional[str] = None,
        standards: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[str]:
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            add_limit_gap(
                "Stopped recording evidence after %d items; findings may be incomplete."
                % MAX_EVIDENCE_ITEMS
            )
            return None
        evidence_id = "CSO-EV-" + _sha256(
            "\0".join((module, kind, file.relative_path, str(line), title))
        )[:12].upper()
        location: dict[str, Any] = {
            "path": file.relative_path,
            "line": max(1, line),
            "sha256": file.sha256,
        }
        if preview is not None:
            location["preview"] = _safe_preview(preview)
        evidence.append(
            {
                "id": evidence_id,
                "module": module,
                "kind": kind,
                "title": title,
                "classification": classification,
                "disposition": disposition,
                "severityHint": severity,
                "confidence": confidence,
                "location": location,
                "verifiedFact": verified_fact,
                "inference": inference,
                "standards": standards or [],
                "metadata": metadata or {},
            }
        )
        if file.client_accessible:
            current = exposure_by_path.setdefault(
                file.relative_path,
                {
                    "path": file.relative_path,
                    "artifactType": _classify_artifact(file.relative_path, file.text),
                    "classification": "required-public-data",
                    "sha256": file.sha256,
                    "evidenceIds": [],
                },
            )
            current["classification"] = _strongest_classification(current["classification"], classification)
            current["evidenceIds"].append(evidence_id)
        return evidence_id

    for file in files:
        for pattern_name, pattern in SUSPICIOUS_INSTRUCTIONS:
            match = pattern.search(file.text)
            if not match:
                continue
            line = _line_number(file.text, match.start())
            instruction_id = "CSO-INJ-" + _sha256("\0".join((pattern_name, file.relative_path, str(line))))[:12].upper()
            preview = _safe_preview(_line_at(file.text, line))
            if len(suspicious) < MAX_SUSPICIOUS_INSTRUCTIONS:
                suspicious.append(
                    {
                        "id": instruction_id,
                        "path": file.relative_path,
                        "line": line,
                        "pattern": pattern_name,
                        "sha256": file.sha256,
                        "preview": preview,
                        "actionTaken": "reported-not-obeyed",
                    }
                )
            else:
                add_limit_gap(
                    "Stopped recording suspicious instructions after %d items; findings may be incomplete."
                    % MAX_SUSPICIOUS_INSTRUCTIONS
                )
            add_evidence(
                module="scanner-self-protection",
                kind="hostile-scanned-instruction",
                title="Instruction-like content attempted to influence an auditor",
                classification="unknown",
                disposition="informational",
                severity="INFO",
                confidence=10,
                file=file,
                line=line,
                preview=preview,
                verified_fact="The file contains text matching the %s scanner-defense pattern." % pattern_name,
                inference="The content may be benign test data or documentation; it was treated as evidence and was not executed or obeyed.",
            )

        for finding in _secret_matches(file.text):
            line_text = _line_at(file.text, finding["line"])
            public_identifier = bool(
                finding["intentionallyPublic"]
                or (
                    finding["patternId"] == "google.api_key"
                    and file.client_accessible
                    and CLIENT_ENV_PREFIX.search(line_text)
                )
            )
            classification = "required-public-data" if public_identifier else "secret"
            exposed = file.client_accessible
            add_evidence(
                module="secret-scanning",
                kind=(
                    "intentional-public-identifier"
                    if public_identifier
                    else "client-accessible-sensitive-value"
                    if exposed
                    else "source-sensitive-value"
                ),
                title=(
                    "Client identifier recognized as intentionally public"
                    if public_identifier
                    else "Sensitive value detected in browser-accessible content"
                    if exposed
                    else "Sensitive value detected in repository source"
                ),
                classification=classification,
                disposition="informational" if public_identifier else "verified-exposure" if exposed else "candidate-finding",
                severity="INFO" if public_identifier else "CRITICAL" if exposed else finding["tier"],
                confidence=9 if public_identifier else 10 if exposed else 8,
                file=file,
                line=finding["line"],
                preview=line_text,
                verified_fact="The JStack CSO redaction taxonomy identified %s%s." % (
                    finding["patternId"],
                    " in a browser-accessible file" if exposed else "",
                ),
                inference=(
                    "Public identifiers still require provider-side origin, scope, quota, and abuse controls."
                    if public_identifier
                    else "A user receiving this artifact can inspect the value. Rotation and server-side isolation may be required."
                    if exposed
                    else "Manual verification is required to establish whether the value is active and reachable."
                ),
                standards=[] if public_identifier else ["OWASP Secrets Management Cheat Sheet"],
                metadata={
                    "patternId": finding["patternId"],
                    "patternTier": finding["tier"],
                    "publicIdentifier": public_identifier,
                    "browserAccessible": exposed,
                },
            )

        if file.relative_path.endswith(".map") and file.client_accessible and not PRIVATE_ARTIFACT_PATH.search(file.relative_path):
            add_evidence(
                module="reverse-engineering",
                kind="public-source-map",
                title="Source map is located in a browser-accessible artifact path",
                classification="debug-information",
                disposition="verified-exposure",
                severity="MEDIUM",
                confidence=10,
                file=file,
                line=1,
                verified_fact="A .map file exists under a path classified as browser-accessible.",
                inference="Deployment verification is still required to prove that the file is publicly served.",
                standards=["OWASP API8:2023 Security Misconfiguration"],
            )

        hydration = re.search(r"__NEXT_DATA__|dehydrat(?:e|ed)|initialState|__APOLLO_STATE__", file.text, re.I)
        if file.client_accessible and hydration:
            line = _line_number(file.text, hydration.start())
            sensitive = bool(SENSITIVE_NAME.search(_line_at(file.text, line)))
            add_evidence(
                module="client-exposure",
                kind="hydration-data",
                title="Client hydration payload detected",
                classification="sensitive-data" if sensitive else "unknown",
                disposition="candidate-finding" if sensitive else "informational",
                severity="HIGH" if sensitive else "INFO",
                confidence=8,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="The browser-accessible file contains a recognized hydration-state marker.",
                inference="Inspect the serialized fields against what the rendered interface actually requires.",
            )

        for storage in re.finditer(r"\b(localStorage|sessionStorage|indexedDB)\b[^\n]{0,180}", file.text):
            line = _line_number(file.text, storage.start())
            sensitive = bool(SENSITIVE_NAME.search(storage.group(0)))
            add_evidence(
                module="client-exposure",
                kind="browser-storage",
                title="Sensitive value may be persisted in browser storage" if sensitive else "Browser storage use detected",
                classification="sensitive-data" if sensitive else "authorized-user-data",
                disposition="candidate-finding" if sensitive else "informational",
                severity="HIGH" if sensitive else "INFO",
                confidence=8 if sensitive else 6,
                file=file,
                line=line,
                preview=storage.group(0),
                verified_fact="%s is referenced in the file." % storage.group(1),
                inference="Browser storage is inspectable and may be exposed to script execution or shared-device access." if sensitive else None,
            )

        client_auth = re.search(r"(?:user\??\.role|isAdmin|hasRole|entitlement|subscriptionTier)", file.text, re.I)
        if file.client_accessible and client_auth:
            line = _line_number(file.text, client_auth.start())
            add_evidence(
                module="authorization",
                kind="client-authorization-signal",
                title="Authorization-like decision appears in client-accessible code",
                classification="authorized-user-data",
                disposition="candidate-finding",
                severity="MEDIUM",
                confidence=6,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="Client-accessible code contains a role, administrator, entitlement, or subscription decision signal.",
                inference="Verify that the server independently enforces the same decision; the client check alone provides no authorization boundary.",
                standards=["OWASP API5:2023 Broken Function Level Authorization"],
            )

        hidden = re.search(r"(?:display\s*:\s*none|\bhidden\b|aria-hidden)[^\n]{0,240}", file.text, re.I)
        if file.client_accessible and hidden and (SENSITIVE_NAME.search(hidden.group(0)) or PROPRIETARY_NAME.search(hidden.group(0))):
            line = _line_number(file.text, hidden.start())
            proprietary = bool(PROPRIETARY_NAME.search(hidden.group(0)))
            add_evidence(
                module="client-exposure",
                kind="hidden-dom-sensitive-data",
                title="Sensitive or proprietary content appears in hidden DOM data",
                classification="proprietary-logic" if proprietary else "sensitive-data",
                disposition="verified-exposure",
                severity="HIGH",
                confidence=9,
                file=file,
                line=line,
                preview=hidden.group(0),
                verified_fact="A browser-accessible file combines hidden-content markup with a sensitive or proprietary identifier.",
                inference="Hidden DOM content remains inspectable and should not be used as a secrecy boundary.",
            )

        proprietary_math = PROPRIETARY_NAME.search(file.text) and re.search(r"[+*/-]\s*(?:\d|[A-Za-z_$])", file.text)
        if proprietary_math:
            marker = PROPRIETARY_NAME.search(file.text)
            assert marker is not None
            line = _line_number(file.text, marker.start())
            add_evidence(
                module="business-logic",
                kind="client-proprietary-calculation" if file.client_accessible else "server-side-proprietary-calculation",
                title="Potential proprietary calculation executes in client-accessible code" if file.client_accessible else "Potential proprietary calculation is isolated from browser delivery",
                classification="proprietary-logic",
                disposition="candidate-finding" if file.client_accessible else "control-present",
                severity="HIGH" if file.client_accessible else "INFO",
                confidence=7,
                file=file,
                line=line,
                preview=_line_at(file.text, line) if file.client_accessible else None,
                verified_fact=(
                    "Client-accessible code contains scoring/weighting terminology and arithmetic operations."
                    if file.client_accessible
                    else "Scoring/weighting terminology and arithmetic were found in a file not classified as client-accessible."
                ),
                inference=(
                    "Product ownership must decide whether the calculation is ordinary presentation logic or a proprietary model that belongs server-side."
                    if file.client_accessible
                    else "Runtime architecture still requires verification before treating this as a complete secrecy boundary."
                ),
            )

        direct_ai = re.search(r"(?:systemPrompt|system_prompt|role\s*:\s*['\"]system['\"])[\s\S]{0,500}(?:\$\{|req\.|request\.|userInput|user_input|params\.|body\.)", file.text, re.I)
        if direct_ai:
            line = _line_number(file.text, direct_ai.start())
            add_evidence(
                module="ai-security",
                kind="untrusted-system-instruction-flow",
                title="Untrusted input may enter system-level model instructions",
                classification="sensitive-data",
                disposition="candidate-finding",
                severity="CRITICAL",
                confidence=7,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="A system-prompt marker and a user-controlled input marker occur within the same bounded code region.",
                inference="Trace the complete data flow to distinguish unsafe instruction interpolation from structured user-message placement.",
                standards=["OWASP LLM01:2025 Prompt Injection"],
            )

        indirect_ai = re.search(r"(?:retriev(?:ed|al)?|document|webpage|email|toolOutput|tool_output|searchResult|search_result)[\s\S]{0,600}(?:systemPrompt|system_prompt|tool_choice|function_call|execute|dispatch)", file.text, re.I)
        if indirect_ai:
            line = _line_number(file.text, indirect_ai.start())
            add_evidence(
                module="ai-security",
                kind="indirect-instruction-flow",
                title="Retrieved or third-party content may reach a privileged AI context",
                classification="sensitive-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=7,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="A retrieved/third-party content marker and a privileged prompt, tool, or execution marker occur within the same bounded code region.",
                inference="Trace structural separation, tool permissions, output validation, and resource authorization before verification.",
                standards=["OWASP LLM01:2025 Prompt Injection"],
            )

        execution = re.search(r"(?:eval|exec|new Function)\s*\(", file.text)
        if execution and re.search(r"(?:llm|model|assistant|completion|generated)", file.text, re.I):
            line = _line_number(file.text, execution.start())
            add_evidence(
                module="ai-security",
                kind="model-output-execution",
                title="Model-derived output may reach executable evaluation",
                classification="sensitive-data",
                disposition="candidate-finding",
                severity="CRITICAL",
                confidence=8,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="Executable evaluation and model-output terminology occur in the same file.",
                inference="A full data-flow trace is required to prove model output reaches the execution sink.",
                standards=["OWASP LLM01:2025 Prompt Injection"],
            )

        unsafe_html = re.search(r"(?:dangerouslySetInnerHTML|v-html|\.innerHTML\s*=)", file.text)
        if unsafe_html and re.search(r"(?:llm|model|assistant|completion|generated)", file.text, re.I):
            line = _line_number(file.text, unsafe_html.start())
            add_evidence(
                module="ai-security",
                kind="unsafe-model-output-rendering",
                title="Model-derived output may reach an unsafe HTML rendering sink",
                classification="sensitive-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=8,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="An HTML escape hatch and model-output terminology occur in the same file.",
                inference="Confirm whether sanitization and a restrictive rendering policy are applied before the sink.",
            )

        tools = re.search(r"(?:tools|function_call|tool_choice)\s*[:=]", file.text)
        if tools:
            validation = bool(re.search(r"(?:zod|schema|validate|allowlist|permission|authorize|humanApproval|requireApproval)", file.text, re.I))
            line = _line_number(file.text, tools.start())
            add_evidence(
                module="ai-security",
                kind="tool-validation-present" if validation else "tool-validation-not-evident",
                title="Model tool validation signal detected" if validation else "Model tools are configured without an evident validation boundary",
                classification="sensitive-data",
                disposition="control-present" if validation else "candidate-finding",
                severity="INFO" if validation else "HIGH",
                confidence=7,
                file=file,
                line=line,
                verified_fact=(
                    "Tool configuration and a validation/authorization signal occur in the same file."
                    if validation
                    else "Tool configuration exists, but no validation, authorization, allowlist, or approval signal was found in the same file."
                ),
                inference=(
                    "Trace middleware and runtime enforcement before considering the tool boundary verified."
                    if validation
                    else "Manual tracing is required because validation may be implemented in another module."
                ),
                standards=["OWASP LLM01:2025 Prompt Injection"],
            )

        verbose_error = re.search(r"(?:\.json|\.send|Response\.json|NextResponse\.json)\s*\([^\n]{0,220}(?:err(?:or)?\.stack|err(?:or)?\.message|stackTrace)", file.text, re.I)
        if verbose_error:
            line = _line_number(file.text, verbose_error.start())
            add_evidence(
                module="browser-security",
                kind="verbose-error-response",
                title="Detailed error information may be returned to a client",
                classification="debug-information",
                disposition="candidate-finding",
                severity="MEDIUM",
                confidence=8,
                file=file,
                line=line,
                preview=verbose_error.group(0),
                verified_fact="An API response construction includes an error stack, message, or stack-trace marker.",
                inference="Confirm production error middleware behavior and whether the response is externally reachable.",
                standards=["OWASP REST Security Cheat Sheet"],
            )

        introspection = re.search(r"introspection\s*:\s*true|graphiql\s*:\s*true", file.text, re.I)
        if introspection:
            add_evidence(
                module="reverse-engineering",
                kind="graphql-introspection-enabled",
                title="GraphQL introspection or GraphiQL is explicitly enabled",
                classification="unnecessary-metadata",
                disposition="candidate-finding",
                severity="MEDIUM",
                confidence=9,
                file=file,
                line=_line_number(file.text, introspection.start()),
                preview=introspection.group(0),
                verified_fact="The configuration explicitly enables a GraphQL discovery feature.",
                inference="Determine whether this configuration reaches production and whether access is appropriately restricted.",
                standards=["OWASP API8:2023 Security Misconfiguration"],
            )

    client_properties = _extract_client_properties(files)
    api_properties: list[dict[str, Any]] = []
    for file in files:
        endpoints = _endpoint_names(file)
        if not endpoints:
            continue
        response_properties = _extract_response_properties(file.text)
        observed = sorted(prop for prop in response_properties if prop in client_properties)
        unused = sorted(prop for prop in response_properties if prop not in client_properties)
        authorization_signals: list[str] = []
        for name, pattern in (
            ("object", r"(?:canAccess|authorize|permission|ownership|ownerId\s*===|userId\s*===)"),
            ("tenant", r"(?:requireTenant|tenantMembership|workspaceMembership|assertTenant|scopeToTenant)"),
            ("role", r"(?:requireRole|hasRole|entitlement|subscription|isAdmin)"),
        ):
            if re.search(pattern, file.text, re.I):
                authorization_signals.append(name)
        dto = bool(re.search(r"(?:DTO|serializer|\.pick\(|\.select\(|z\.object\(|allowlist|allowedFields)", file.text, re.I))
        raw_upstream = bool(re.search(r"(?:\.json|\.send|Response\.json|NextResponse\.json)\s*\(\s*(?:response|upstream|provider|result)\.(?:data|body)|return\s+(?:response|upstream|provider)\b", file.text, re.I))
        for endpoint in endpoints:
            api_properties.append(
                {
                    "endpoint": endpoint,
                    "sourcePath": file.relative_path,
                    "responseProperties": response_properties,
                    "observedClientProperties": observed,
                    "unusedCandidateProperties": unused,
                    "authorizationSignals": authorization_signals,
                    "dtoAllowlistDetected": dto,
                    "rawUpstreamResponseCandidate": raw_upstream,
                    "confidence": 7 if response_properties else 4,
                }
            )

        if raw_upstream:
            marker = re.search(r"(?:response|upstream|provider|result)\.(?:data|body)", file.text, re.I)
            add_evidence(
                module="api-minimization",
                kind="raw-upstream-response",
                title="Endpoint may return a raw upstream-provider response",
                classification="unnecessary-metadata",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=8,
                file=file,
                line=_line_number(file.text, marker.start()) if marker else 1,
                verified_fact="The endpoint response expression directly references an upstream/provider response body.",
                inference="Verify the runtime shape and replace passthrough behavior with an explicit response DTO where confirmed.",
                standards=["OWASP API3:2023 Broken Object Property Level Authorization", "OWASP API10:2023 Unsafe Consumption of APIs"],
            )

        sensitive_unused = [prop for prop in unused if SENSITIVE_NAME.search(prop)]
        if sensitive_unused and not dto:
            add_evidence(
                module="api-minimization",
                kind="unused-sensitive-response-properties",
                title="Sensitive response properties have no observed client consumer",
                classification="sensitive-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=6,
                file=file,
                line=1,
                verified_fact="The response declares sensitive-looking properties not observed in statically recognized client access: %s." % ", ".join(sensitive_unused),
                inference="Dynamic property access may exist; confirm with runtime evidence before removal.",
                standards=["OWASP API3:2023 Broken Object Property Level Authorization"],
                metadata={"properties": ",".join(sensitive_unused)},
            )

        sensitive_response = [prop for prop in response_properties if SENSITIVE_NAME.search(prop)]
        if sensitive_response and not authorization_signals:
            add_evidence(
                module="authorization",
                kind="property-authorization-not-evident",
                title="Sensitive response properties lack an evident property-level authorization decision",
                classification="sensitive-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=6,
                file=file,
                line=1,
                verified_fact="The response declares sensitive-looking properties and no recognized authorization signal exists in the same file: %s." % ", ".join(sensitive_response),
                inference="Authorization may be enforced by middleware or the data layer; trace it before verification.",
                standards=["OWASP API3:2023 Broken Object Property Level Authorization"],
            )

        identifier = re.search(r"(?:params|query|body)\??\.\w*(?:id|Id)\b|\[(?:['\"]id['\"])\]", file.text)
        if identifier and not authorization_signals:
            add_evidence(
                module="authorization",
                kind="object-authorization-not-evident",
                title="User-controlled object identifier lacks an evident authorization check",
                classification="authorized-user-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=6,
                file=file,
                line=_line_number(file.text, identifier.start()),
                preview=identifier.group(0),
                verified_fact="The endpoint consumes an identifier from request-controlled data and no recognized authorization signal exists in the same file.",
                inference="Authorization may exist in middleware or data-access policy; trace the complete request path before verification.",
                standards=["OWASP API1:2023 Broken Object Level Authorization"],
            )

        tenant = re.search(r"(?:tenantId|tenant_id|workspaceId|workspace_id)\b", file.text, re.I)
        if tenant and "tenant" not in authorization_signals:
            line = _line_number(file.text, tenant.start())
            add_evidence(
                module="authorization",
                kind="tenant-isolation-not-evident",
                title="Tenant or workspace identifier lacks an evident membership boundary",
                classification="authorized-user-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=6,
                file=file,
                line=line,
                preview=_line_at(file.text, line),
                verified_fact="The endpoint references a tenant/workspace identifier but no recognized tenant membership or scoping control exists in the same file.",
                inference="Database row-level security or upstream middleware may provide isolation; require evidence before verification.",
                standards=["OWASP API1:2023 Broken Object Level Authorization"],
            )

        if any(re.search(r"(?:admin|manage|internal)", endpoint, re.I) for endpoint in endpoints) and "role" not in authorization_signals:
            add_evidence(
                module="authorization",
                kind="function-authorization-not-evident",
                title="Administrative function lacks an evident role or entitlement decision",
                classification="authorized-user-data",
                disposition="candidate-finding",
                severity="HIGH",
                confidence=6,
                file=file,
                line=1,
                verified_fact="The discovered route name indicates an administrative/internal function and no recognized role or entitlement control exists in the same file.",
                inference="Route groups or gateway policy may enforce authorization; verify the complete path before reporting a vulnerability.",
                standards=["OWASP API5:2023 Broken Function Level Authorization"],
            )

        if any(re.search(r"(?:export|bulk|score|research|history|search|ai|admin)", endpoint, re.I) for endpoint in endpoints):
            rate_limit = bool(re.search(r"(?:rateLimit|rateLimiter|throttle|quota|tokenBucket)", file.text, re.I))
            bounded = bool(re.search(r"(?:limit|take|pageSize|maxRows|maxRange|bounded|pagination)", file.text, re.I))
            detection = bool(re.search(r"(?:scrap|enumerat|velocity|anomal|suspicious|abuse)[\s\S]*?(?:log|alert|detect|monitor)", file.text, re.I))
            if not rate_limit or not bounded:
                add_evidence(
                    module="abuse-detection",
                    kind="sensitive-flow-extraction-controls-not-evident",
                    title="Sensitive business-flow endpoint lacks evident extraction controls",
                    classification="proprietary-logic",
                    disposition="candidate-finding",
                    severity="MEDIUM",
                    confidence=6,
                    file=file,
                    line=1,
                    verified_fact="A sensitive-flow route was identified; rate-limit signal=%s, bounded-query signal=%s." % (str(rate_limit).lower(), str(bounded).lower()),
                    inference="Controls may be enforced by an API gateway; require deployment evidence before verification.",
                    standards=["OWASP API4:2023 Unrestricted Resource Consumption", "OWASP API6:2023 Unrestricted Access to Sensitive Business Flows"],
                )
            if detection:
                add_evidence(
                    module="abuse-detection",
                    kind="scraping-detection-signal",
                    title="Scraping or enumeration monitoring signal detected",
                    classification="proprietary-logic",
                    disposition="control-present",
                    severity="INFO",
                    confidence=7,
                    file=file,
                    line=1,
                    verified_fact="The endpoint implementation contains scraping/enumeration terminology and logging, alerting, detection, or monitoring terminology.",
                    inference="Operational alert routing and response evidence still require manual verification.",
                )

    for file in files:
        if file.client_accessible and file.relative_path not in exposure_by_path:
            exposure_by_path[file.relative_path] = {
                "path": file.relative_path,
                "artifactType": _classify_artifact(file.relative_path, file.text),
                "classification": "required-public-data",
                "sha256": file.sha256,
                "evidenceIds": [],
            }

    build_artifacts_present = any(file.build_artifact for file in files)
    if not build_artifacts_present:
        gaps.append(
            {
                "path": ".",
                "reason": "artifact-not-present",
                "detail": "No existing production build-artifact directory was detected. The analyzer did not run a project build.",
            }
        )

    evidence.sort(key=lambda item: item["id"])
    suspicious.sort(key=lambda item: item["id"])
    api_properties.sort(key=lambda item: (item["sourcePath"], item["endpoint"]))
    client_exposure = []
    for item in exposure_by_path.values():
        item["evidenceIds"] = sorted(set(item["evidenceIds"]))
        client_exposure.append(item)
    client_exposure.sort(key=lambda item: item["path"])
    repository_fingerprint = _sha256(
        "\n".join(sorted("%s\0%s" % (file.relative_path, file.sha256) for file in files))
    )

    return {
        "schemaVersion": EVIDENCE_SCHEMA_VERSION,
        "generatedAt": _iso_datetime(now),
        "repository": {
            "name": repository_root.name,
            "fingerprint": repository_fingerprint,
            "fileCount": len(files),
            "byteCount": sum(file.size for file in files),
        },
        "policy": {
            "browserDeliveredContentIsInspectable": True,
            "readOnlyProjectInspection": True,
            "networkRequestsPermitted": False,
            "projectCommandsPermitted": False,
            "rawSecretsRetained": False,
        },
        "limits": resolved_limits,
        "stack": _detect_stack(files),
        "coverage": {
            "filesScanned": len(files),
            "bytesScanned": sum(file.size for file in files),
            "filesSkipped": len(gaps),
            "complete": not gaps,
            "buildArtifactsPresent": build_artifacts_present,
            "gaps": sorted(gaps, key=lambda item: (item["path"], item["reason"])),
        },
        "clientExposure": client_exposure,
        "apiProperties": api_properties,
        "suspiciousInstructions": suspicious,
        "evidence": evidence,
        "summary": {
            "byModule": dict(sorted(Counter(item["module"] for item in evidence).items())),
            "byDisposition": dict(sorted(Counter(item["disposition"] for item in evidence).items())),
            "bySeverityHint": dict(sorted(Counter(item["severityHint"] for item in evidence).items())),
        },
    }


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _unknown_keys(value: Mapping[str, Any], allowed: set[str], context: str) -> list[str]:
    return ["%s contains unknown field %r" % (context, key) for key in value if key not in allowed]


def _missing_keys(value: Mapping[str, Any], required: Iterable[str], context: str) -> list[str]:
    return ["%s.%s is required" % (context, key) for key in required if key not in value]


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_datetime(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}T", value))


def _repository_relative(value: Any, *, allow_dot: bool = False) -> bool:
    if not _non_empty_string(value) or "\0" in value:
        return False
    normalized = value.replace("\\", "/")
    if PurePosixPath(normalized).is_absolute() or PureWindowsPath(value).is_absolute():
        return False
    if not allow_dot and normalized == ".":
        return False
    return ".." not in PurePosixPath(normalized).parts


def _unique_strings(value: Any, context: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        return ["%s must be an array" % context]
    errors: list[str] = []
    if not allow_empty and not value:
        errors.append("%s must not be empty" % context)
    if any(not _non_empty_string(item) for item in value):
        errors.append("%s must contain non-empty strings" % context)
    if len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
        errors.append("%s must not contain duplicates" % context)
    return errors


def _redaction_errors(value: Any, label: str) -> list[str]:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
    leaked = [match for match in _secret_matches(serialized) if not match["intentionallyPublic"]]
    return ["%s contains %d unredacted secret-like value(s)" % (label, len(leaked))] if leaked else []


def validate_evidence_bundle(value: Any) -> list[str]:
    top_keys = {
        "schemaVersion", "generatedAt", "repository", "policy", "limits", "stack",
        "coverage", "clientExposure", "apiProperties", "suspiciousInstructions",
        "evidence", "summary",
    }
    if not _is_record(value):
        return ["evidence bundle must be an object"]
    errors = _unknown_keys(value, top_keys, "evidence bundle")
    errors += _missing_keys(value, top_keys, "evidence bundle")
    if value.get("schemaVersion") != EVIDENCE_SCHEMA_VERSION:
        errors.append("schemaVersion must be %s" % EVIDENCE_SCHEMA_VERSION)
    if not _valid_datetime(value.get("generatedAt")):
        errors.append("generatedAt must be an ISO-8601 datetime")

    repository = value.get("repository")
    if not _is_record(repository):
        errors.append("repository must be an object")
    else:
        required = {"name", "fingerprint", "fileCount", "byteCount"}
        errors += _unknown_keys(repository, required, "repository")
        errors += _missing_keys(repository, required, "repository")
        if not _non_empty_string(repository.get("name")):
            errors.append("repository.name must be a non-empty string")
        if not re.fullmatch(r"[a-f0-9]{64}", str(repository.get("fingerprint", ""))):
            errors.append("repository.fingerprint must be a lowercase SHA-256 digest")
        for key in ("fileCount", "byteCount"):
            if isinstance(repository.get(key), bool) or not isinstance(repository.get(key), int) or repository[key] < 0:
                errors.append("repository.%s must be a non-negative integer" % key)

    policy = value.get("policy")
    expected_policy = {
        "browserDeliveredContentIsInspectable": True,
        "readOnlyProjectInspection": True,
        "networkRequestsPermitted": False,
        "projectCommandsPermitted": False,
        "rawSecretsRetained": False,
    }
    if not _is_record(policy):
        errors.append("policy must be an object")
    else:
        errors += _unknown_keys(policy, set(expected_policy), "policy")
        errors += _missing_keys(policy, expected_policy, "policy")
        for key, expected in expected_policy.items():
            if policy.get(key) is not expected:
                errors.append("policy.%s must be %s" % (key, str(expected).lower()))

    bundle_limits = value.get("limits")
    if not _is_record(bundle_limits):
        errors.append("limits must be an object")
    else:
        errors += _unknown_keys(bundle_limits, set(DEFAULT_LIMITS), "limits")
        errors += _missing_keys(bundle_limits, DEFAULT_LIMITS, "limits")
        for key in DEFAULT_LIMITS:
            current = bundle_limits.get(key)
            if isinstance(current, bool) or not isinstance(current, int) or current <= 0:
                errors.append("limits.%s must be a positive integer" % key)
            elif current > MAX_LIMITS[key]:
                errors.append("limits.%s must not exceed %d" % (key, MAX_LIMITS[key]))

    stack_value = value.get("stack")
    if not _is_record(stack_value):
        errors.append("stack must be an object")
    else:
        stack_keys = {"languages", "frameworks", "adapters"}
        errors += _unknown_keys(stack_value, stack_keys, "stack")
        errors += _missing_keys(stack_value, stack_keys, "stack")
        for key in stack_keys:
            errors += _unique_strings(stack_value.get(key), "stack.%s" % key)

    coverage = value.get("coverage")
    if not _is_record(coverage):
        errors.append("coverage must be an object")
    else:
        coverage_keys = {"filesScanned", "bytesScanned", "filesSkipped", "complete", "buildArtifactsPresent", "gaps"}
        errors += _unknown_keys(coverage, coverage_keys, "coverage")
        errors += _missing_keys(coverage, coverage_keys, "coverage")
        for key in ("filesScanned", "bytesScanned", "filesSkipped"):
            current = coverage.get(key)
            if isinstance(current, bool) or not isinstance(current, int) or current < 0:
                errors.append("coverage.%s must be a non-negative integer" % key)
        if not isinstance(coverage.get("complete"), bool):
            errors.append("coverage.complete must be boolean")
        if not isinstance(coverage.get("buildArtifactsPresent"), bool):
            errors.append("coverage.buildArtifactsPresent must be boolean")
        gaps = coverage.get("gaps")
        if not isinstance(gaps, list):
            errors.append("coverage.gaps must be an array")
        else:
            for index, gap in enumerate(gaps):
                context = "coverage.gaps[%d]" % index
                if not _is_record(gap):
                    errors.append("%s must be an object" % context)
                    continue
                keys = {"path", "reason", "detail"}
                errors += _unknown_keys(gap, keys, context)
                errors += _missing_keys(gap, keys, context)
                if not _repository_relative(gap.get("path"), allow_dot=True):
                    errors.append("%s.path must be repository-relative" % context)
                if gap.get("reason") not in COVERAGE_GAP_REASONS:
                    errors.append("%s.reason is invalid" % context)
                if not _non_empty_string(gap.get("detail")):
                    errors.append("%s.detail must be a non-empty string" % context)
            if coverage.get("filesSkipped") != len(gaps):
                errors.append("coverage.filesSkipped must equal coverage.gaps.length")
            if coverage.get("complete") is not (len(gaps) == 0):
                errors.append("coverage.complete must reflect whether coverage.gaps is empty")
            artifact_gap = any(isinstance(gap, dict) and gap.get("reason") == "artifact-not-present" for gap in gaps)
            if coverage.get("buildArtifactsPresent") is artifact_gap:
                errors.append("coverage.buildArtifactsPresent conflicts with artifact-not-present coverage evidence")

    evidence_value = value.get("evidence")
    evidence_records: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    if not isinstance(evidence_value, list):
        errors.append("evidence must be an array")
    else:
        for index, item in enumerate(evidence_value):
            context = "evidence[%d]" % index
            if not _is_record(item):
                errors.append("%s must be an object" % context)
                continue
            evidence_records.append(item)
            keys = {"id", "module", "kind", "title", "classification", "disposition", "severityHint", "confidence", "location", "verifiedFact", "inference", "standards", "metadata"}
            errors += _unknown_keys(item, keys, context)
            errors += _missing_keys(item, keys, context)
            if not _non_empty_string(item.get("id")):
                errors.append("%s.id must be a non-empty string" % context)
            elif item["id"] in evidence_ids:
                errors.append("evidence IDs must be unique")
            else:
                evidence_ids.add(item["id"])
            if item.get("module") not in ENTERPRISE_MODULES:
                errors.append("%s.module is invalid" % context)
            if item.get("classification") not in EXPOSURE_CLASSIFICATIONS:
                errors.append("%s.classification is invalid" % context)
            if item.get("disposition") not in EVIDENCE_DISPOSITIONS:
                errors.append("%s.disposition is invalid" % context)
            if item.get("severityHint") not in SEVERITIES:
                errors.append("%s.severityHint is invalid" % context)
            confidence = item.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 10:
                errors.append("%s.confidence must be between 0 and 10" % context)
            location = item.get("location")
            if not _is_record(location):
                errors.append("%s.location must be an object" % context)
            else:
                location_keys = {"path", "line", "sha256", "preview"}
                errors += _unknown_keys(location, location_keys, "%s.location" % context)
                errors += _missing_keys(location, {"path", "line", "sha256"}, "%s.location" % context)
                if not _repository_relative(location.get("path")):
                    errors.append("%s.location.path must be repository-relative" % context)
                if isinstance(location.get("line"), bool) or not isinstance(location.get("line"), int) or location["line"] < 1:
                    errors.append("%s.location.line must be a positive integer" % context)
                if not re.fullmatch(r"[a-f0-9]{64}", str(location.get("sha256", ""))):
                    errors.append("%s.location.sha256 is invalid" % context)
            errors += _unique_strings(item.get("standards"), "%s.standards" % context)
            if not isinstance(item.get("metadata"), dict) or any(not isinstance(entry, (str, int, float, bool, type(None))) for entry in item.get("metadata", {}).values()):
                errors.append("%s.metadata values must be scalar JSON values" % context)

    exposure_value = value.get("clientExposure")
    if not isinstance(exposure_value, list):
        errors.append("clientExposure must be an array")
    else:
        seen_paths: set[str] = set()
        for index, item in enumerate(exposure_value):
            context = "clientExposure[%d]" % index
            if not _is_record(item):
                errors.append("%s must be an object" % context)
                continue
            keys = {"path", "artifactType", "classification", "sha256", "evidenceIds"}
            errors += _unknown_keys(item, keys, context)
            errors += _missing_keys(item, keys, context)
            if not _repository_relative(item.get("path")):
                errors.append("%s.path must be a confined repository-relative path" % context)
            elif item["path"] in seen_paths:
                errors.append("clientExposure paths must be unique")
            else:
                seen_paths.add(item["path"])
            if item.get("classification") not in EXPOSURE_CLASSIFICATIONS:
                errors.append("%s.classification is invalid" % context)
            errors += _unique_strings(item.get("evidenceIds"), "%s.evidenceIds" % context)
            for evidence_id in item.get("evidenceIds", []):
                if isinstance(evidence_id, str) and evidence_id not in evidence_ids:
                    errors.append("clientExposure references unknown evidence ID %r" % evidence_id)

    api_value = value.get("apiProperties")
    if not isinstance(api_value, list):
        errors.append("apiProperties must be an array")
    else:
        for index, item in enumerate(api_value):
            context = "apiProperties[%d]" % index
            if not _is_record(item):
                errors.append("%s must be an object" % context)
                continue
            keys = {"endpoint", "sourcePath", "responseProperties", "observedClientProperties", "unusedCandidateProperties", "authorizationSignals", "dtoAllowlistDetected", "rawUpstreamResponseCandidate", "confidence"}
            errors += _unknown_keys(item, keys, context)
            errors += _missing_keys(item, keys, context)
            if not _repository_relative(item.get("sourcePath")):
                errors.append("%s.sourcePath must be repository-relative" % context)
            for key in ("responseProperties", "observedClientProperties", "unusedCandidateProperties", "authorizationSignals"):
                errors += _unique_strings(item.get(key), "%s.%s" % (context, key))

    suspicious_value = value.get("suspiciousInstructions")
    if not isinstance(suspicious_value, list):
        errors.append("suspiciousInstructions must be an array")
    else:
        seen_instruction_ids: set[str] = set()
        for index, item in enumerate(suspicious_value):
            context = "suspiciousInstructions[%d]" % index
            if not _is_record(item):
                errors.append("%s must be an object" % context)
                continue
            keys = {"id", "path", "line", "pattern", "sha256", "preview", "actionTaken"}
            errors += _unknown_keys(item, keys, context)
            errors += _missing_keys(item, keys, context)
            if not _repository_relative(item.get("path")):
                errors.append("%s.path must be repository-relative" % context)
            if item.get("actionTaken") != "reported-not-obeyed":
                errors.append("%s.actionTaken must be reported-not-obeyed" % context)
            if item.get("id") in seen_instruction_ids:
                errors.append("suspiciousInstructions IDs must be unique")
            elif isinstance(item.get("id"), str):
                seen_instruction_ids.add(item["id"])

    summary = value.get("summary")
    if not _is_record(summary):
        errors.append("summary must be an object")
    else:
        summary_keys = {"byModule", "byDisposition", "bySeverityHint"}
        errors += _unknown_keys(summary, summary_keys, "summary")
        errors += _missing_keys(summary, summary_keys, "summary")
        for key, field in (("byModule", "module"), ("byDisposition", "disposition"), ("bySeverityHint", "severityHint")):
            expected = dict(Counter(item.get(field) for item in evidence_records if isinstance(item.get(field), str)))
            if summary.get(key) != dict(sorted(expected.items())):
                errors.append("summary.%s does not match the evidence array" % key)

    if _is_record(repository) and _is_record(coverage):
        if repository.get("fileCount") != coverage.get("filesScanned"):
            errors.append("repository.fileCount must equal coverage.filesScanned")
        if repository.get("byteCount") != coverage.get("bytesScanned"):
            errors.append("repository.byteCount must equal coverage.bytesScanned")
    errors += _redaction_errors(value, "evidence bundle")
    return errors


REPORT_TOP_LEVEL_KEYS = {
    "version", "date", "mode", "scope", "diff_mode", "phases_run", "modules_run",
    "guarantee_policy", "coverage", "attack_surface", "client_exposure",
    "api_minimization", "authorization_review", "proprietary_logic", "ai_security",
    "scanner_self_protection", "findings", "supply_chain_summary", "filter_stats",
    "totals", "trend",
}

FINDING_KEYS = {
    "id", "finding_id", "title", "severity", "confidence", "status",
    "affected_component", "evidence", "attack_precondition", "potential_impact",
    "verified_fact", "inference", "recommended_remediation", "validation_test",
    "residual_risk", "relevant_standard", "phase", "phase_name", "category",
    "fingerprint", "file", "line", "commit", "description", "exploit_scenario",
    "impact", "recommendation", "playbook", "verification",
}

REQUIRED_FINDING_KEYS = {
    "id", "finding_id", "title", "severity", "confidence", "status",
    "affected_component", "evidence", "attack_precondition", "potential_impact",
    "verified_fact", "inference", "recommended_remediation", "validation_test",
    "residual_risk", "relevant_standard",
}


def validate_security_report(value: Any) -> list[str]:
    if not _is_record(value):
        return ["report must be an object"]
    if value.get("version") == "2.0.0":
        errors = [] if isinstance(value.get("findings"), list) else ["v2.0.0 findings must be an array"]
        return errors + _redaction_errors(value, "report")
    errors = _unknown_keys(value, REPORT_TOP_LEVEL_KEYS, "report")
    required = {
        "version", "date", "mode", "scope", "diff_mode", "phases_run", "modules_run",
        "guarantee_policy", "coverage", "attack_surface", "findings", "filter_stats",
        "totals", "trend",
    }
    errors += _missing_keys(value, required, "report")
    if value.get("version") != REPORT_SCHEMA_VERSION:
        errors.append("version must be 2.0.0 or %s" % REPORT_SCHEMA_VERSION)
    if not _valid_datetime(value.get("date")):
        errors.append("report.date must be an ISO-8601 datetime")
    if value.get("mode") not in {"daily", "comprehensive"}:
        errors.append("report.mode must be daily or comprehensive")
    if value.get("scope") not in {"full", "infra", "code", "appsec", "skills", "supply-chain", "owasp", "focused"}:
        errors.append("report.scope is invalid")
    if not isinstance(value.get("diff_mode"), bool):
        errors.append("report.diff_mode must be boolean")
    phases = value.get("phases_run")
    if not isinstance(phases, list) or any(isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 14 for item in phases):
        errors.append("report.phases_run must contain phase integers from 0 through 14")
    elif len(set(phases)) != len(phases):
        errors.append("report.phases_run must not contain duplicates")
    modules = value.get("modules_run")
    if not isinstance(modules, list) or any(item not in ENTERPRISE_MODULES for item in modules):
        errors.append("report.modules_run contains an unknown enterprise module")
    elif len(set(modules)) != len(modules):
        errors.append("report.modules_run must not contain duplicates")
    guarantee = value.get("guarantee_policy")
    expected_guarantee = {
        "browser_delivered_content_is_inspectable": True,
        "reverse_engineering_prevention_guaranteed": False,
        "prompt_injection_prevention_guaranteed": False,
        "residual_risk_acknowledged": True,
    }
    if not _is_record(guarantee):
        errors.append("report.guarantee_policy must be an object")
    else:
        errors += _unknown_keys(guarantee, set(expected_guarantee), "report.guarantee_policy")
        errors += _missing_keys(guarantee, expected_guarantee, "report.guarantee_policy")
        for key, expected in expected_guarantee.items():
            if guarantee.get(key) is not expected:
                errors.append("report.guarantee_policy.%s must be %s" % (key, str(expected).lower()))
    coverage = value.get("coverage")
    if not _is_record(coverage) or set(coverage) - {"complete", "gaps"} or not isinstance(coverage.get("complete"), bool) or not isinstance(coverage.get("gaps"), list):
        errors.append("report.coverage must include only boolean complete and an array of gaps")
    for key in ("attack_surface", "filter_stats", "totals", "trend"):
        if not _is_record(value.get(key)):
            errors.append("report.%s must be an object" % key)
    for key in ("client_exposure", "api_minimization", "authorization_review", "proprietary_logic", "ai_security", "scanner_self_protection", "supply_chain_summary"):
        if key in value and not _is_record(value[key]):
            errors.append("report.%s must be an object when present" % key)

    findings = value.get("findings")
    if not isinstance(findings, list):
        errors.append("report.findings must be an array")
    else:
        seen_ids: set[str] = set()
        for index, finding in enumerate(findings):
            context = "findings[%d]" % index
            if not _is_record(finding):
                errors.append("%s must be an object" % context)
                continue
            errors += _unknown_keys(finding, FINDING_KEYS, context)
            errors += _missing_keys(finding, REQUIRED_FINDING_KEYS, context)
            if not ((isinstance(finding.get("id"), int) and not isinstance(finding.get("id"), bool)) or _non_empty_string(finding.get("id"))):
                errors.append("%s.id must be a number or non-empty string" % context)
            finding_id = finding.get("finding_id")
            if not _non_empty_string(finding_id):
                errors.append("%s.finding_id must be a non-empty string" % context)
            elif finding_id in seen_ids:
                errors.append("duplicate finding_id %r" % finding_id)
            else:
                seen_ids.add(finding_id)
            if finding.get("severity") not in SEVERITIES:
                errors.append("%s.severity is invalid" % context)
            confidence = finding.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 10:
                errors.append("%s.confidence must be between 0 and 10" % context)
            if finding.get("status") not in {"VERIFIED", "UNVERIFIED", "TENTATIVE"}:
                errors.append("%s.status is invalid" % context)
            for key in ("title", "affected_component", "attack_precondition", "potential_impact", "verified_fact", "recommended_remediation", "validation_test", "residual_risk"):
                if not _non_empty_string(finding.get(key)):
                    errors.append("%s.%s must be a non-empty string" % (context, key))
            if finding.get("inference") is not None and not isinstance(finding.get("inference"), str):
                errors.append("%s.inference must be a string or null" % context)
            errors += _unique_strings(finding.get("relevant_standard"), "%s.relevant_standard" % context)
            references = finding.get("evidence")
            if not isinstance(references, list) or not references:
                errors.append("%s.evidence must contain at least one reference" % context)
            else:
                for evidence_index, reference in enumerate(references):
                    evidence_context = "%s.evidence[%d]" % (context, evidence_index)
                    if not _is_record(reference):
                        errors.append("%s must be an object" % evidence_context)
                        continue
                    ref_keys = {"path", "line", "sha256", "description"}
                    errors += _unknown_keys(reference, ref_keys, evidence_context)
                    errors += _missing_keys(reference, ref_keys, evidence_context)
                    if not _repository_relative(reference.get("path")):
                        errors.append("%s.path must be a confined repository-relative path" % evidence_context)
                    if isinstance(reference.get("line"), bool) or not isinstance(reference.get("line"), int) or reference["line"] < 1:
                        errors.append("%s.line must be a positive integer" % evidence_context)
                    if not re.fullmatch(r"[a-f0-9]{64}", str(reference.get("sha256", ""))):
                        errors.append("%s.sha256 must be a lowercase SHA-256 digest" % evidence_context)
                    if not _non_empty_string(reference.get("description")):
                        errors.append("%s.description must be a non-empty string" % evidence_context)
    return errors + _redaction_errors(value, "report")
