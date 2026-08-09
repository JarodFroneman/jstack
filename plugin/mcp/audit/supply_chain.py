"""Deterministic supply-chain and build-input discovery for Audit Stage 6.

The helpers in this module are deliberately static.  They classify tracked
paths and parse a narrow, security-relevant subset of GitHub Actions syntax;
they never execute repository code, resolve dependencies, contact a registry,
or claim that an advisory database is complete.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Iterable


DEPENDENCY_INVENTORY_SCHEMA_VERSION = "jstack.audit.dependency-inventory.v1"
SUPPLY_CHAIN_REPORT_SCHEMA_VERSION = "jstack.audit.supply-chain-report.v1"

_MAX_WORKFLOW_BYTES = 2_000_000
_ACTION_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
_USES_RE = re.compile(
    r"^(?P<indent>[ ]*)(?:-[ ]*)?uses:[ ]*(?P<quote>['\"]?)(?P<value>[^'\"#\s]+)(?P=quote)(?:[ ]*(?:#.*)?)$"
)
_USES_PREFIX_RE = re.compile(r"^[ \t]*(?:-[ \t]*)?uses:[ \t]*")
_PERMISSIONS_RE = re.compile(
    r"^(?P<indent>[ ]*)permissions:[ ]*(?P<value>[^#]*?)[ ]*(?:#.*)?$"
)
_PERMISSION_ITEM_RE = re.compile(
    r"^(?P<indent>[ ]+)(?P<scope>[A-Za-z0-9_-]+):[ ]*(?P<value>read|write|none)[ ]*(?:#.*)?$"
)


class SupplyChainProtocolError(ValueError):
    """Raised when bounded static supply-chain input is malformed."""


_EXACT_INPUTS: dict[str, tuple[str, str]] = {
    "package.json": ("manifest", "javascript"),
    "package-lock.json": ("lockfile", "javascript"),
    "npm-shrinkwrap.json": ("lockfile", "javascript"),
    "yarn.lock": ("lockfile", "javascript"),
    "pnpm-lock.yaml": ("lockfile", "javascript"),
    "bun.lock": ("lockfile", "javascript"),
    "bun.lockb": ("lockfile", "javascript"),
    "deno.json": ("manifest", "javascript"),
    "deno.jsonc": ("manifest", "javascript"),
    "deno.lock": ("lockfile", "javascript"),
    "pyproject.toml": ("manifest", "python"),
    "pipfile": ("manifest", "python"),
    "pipfile.lock": ("lockfile", "python"),
    "poetry.lock": ("lockfile", "python"),
    "uv.lock": ("lockfile", "python"),
    "pdm.lock": ("lockfile", "python"),
    "pylock.toml": ("lockfile", "python"),
    "pixi.toml": ("manifest", "python"),
    "pixi.lock": ("lockfile", "python"),
    "environment.yml": ("manifest", "python"),
    "environment.yaml": ("manifest", "python"),
    "conda-lock.yml": ("lockfile", "python"),
    "conda-lock.yaml": ("lockfile", "python"),
    "setup.py": ("manifest", "python"),
    "setup.cfg": ("manifest", "python"),
    "cargo.toml": ("manifest", "rust"),
    "cargo.lock": ("lockfile", "rust"),
    "deny.toml": ("policy", "rust"),
    "go.mod": ("manifest", "go"),
    "go.sum": ("lockfile", "go"),
    "go.work": ("manifest", "go"),
    "go.work.sum": ("lockfile", "go"),
    "pom.xml": ("manifest", "jvm"),
    "build.gradle": ("manifest", "jvm"),
    "build.gradle.kts": ("manifest", "jvm"),
    "gradle.lockfile": ("lockfile", "jvm"),
    "libs.versions.toml": ("manifest", "jvm"),
    "settings.gradle": ("build-config", "jvm"),
    "settings.gradle.kts": ("build-config", "jvm"),
    "gradle.properties": ("build-config", "jvm"),
    "verification-metadata.xml": ("policy", "jvm"),
    "gemfile": ("manifest", "ruby"),
    "gemfile.lock": ("lockfile", "ruby"),
    "gems.locked": ("lockfile", "ruby"),
    "composer.json": ("manifest", "php"),
    "composer.lock": ("lockfile", "php"),
    "packages.lock.json": ("lockfile", "dotnet"),
    "directory.packages.props": ("manifest", "dotnet"),
    "packages.config": ("manifest", "dotnet"),
    "nuget.config": ("policy", "dotnet"),
    "directory.build.props": ("build-config", "dotnet"),
    "directory.build.targets": ("build-config", "dotnet"),
    "global.json": ("build-config", "dotnet"),
    "conanfile.py": ("manifest", "cpp"),
    "conanfile.txt": ("manifest", "cpp"),
    "conan.lock": ("lockfile", "cpp"),
    "vcpkg.json": ("manifest", "cpp"),
    "vcpkg-lock.json": ("lockfile", "cpp"),
    "cmakelists.txt": ("build-config", "cpp"),
    "meson.build": ("build-config", "cpp"),
    "workspace": ("build-config", "bazel"),
    "workspace.bazel": ("build-config", "bazel"),
    "module.bazel": ("manifest", "bazel"),
    "package.swift": ("manifest", "swift"),
    "package.resolved": ("lockfile", "swift"),
    "podfile": ("manifest", "swift"),
    "podfile.lock": ("lockfile", "swift"),
    "cartfile": ("manifest", "swift"),
    "cartfile.resolved": ("lockfile", "swift"),
    "pubspec.yaml": ("manifest", "dart"),
    "pubspec.lock": ("lockfile", "dart"),
    "mix.exs": ("manifest", "elixir"),
    "mix.lock": ("lockfile", "elixir"),
    "cabal.project": ("manifest", "haskell"),
    "cabal.project.freeze": ("lockfile", "haskell"),
    "stack.yaml": ("manifest", "haskell"),
    "stack.yaml.lock": ("lockfile", "haskell"),
    "renv.lock": ("lockfile", "r"),
    "dockerfile": ("build-config", "container"),
    "containerfile": ("build-config", "container"),
    "compose.yml": ("build-config", "container"),
    "compose.yaml": ("build-config", "container"),
    "docker-compose.yml": ("build-config", "container"),
    "docker-compose.yaml": ("build-config", "container"),
    "flake.nix": ("manifest", "generic"),
    "flake.lock": ("lockfile", "generic"),
    "default.nix": ("build-config", "generic"),
    "shell.nix": ("build-config", "generic"),
    "makefile": ("build-config", "generic"),
    "justfile": ("build-config", "generic"),
    "taskfile.yml": ("build-config", "generic"),
    "taskfile.yaml": ("build-config", "generic"),
}

_GENERATED_DIRS = {
    "dist",
    "build",
    "out",
    "generated",
    "gen",
    "public/build",
    "public/assets",
    ".next",
    ".nuxt",
    ".output",
    "target",
    "obj",
}


def _safe_path(raw: Any) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 1024:
        raise SupplyChainProtocolError("repository path must be a non-empty bounded string")
    if "\\" in raw or raw.startswith("/") or "//" in raw:
        raise SupplyChainProtocolError("repository path must be normalized and relative")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SupplyChainProtocolError("repository path contains an unsafe segment")
    return path.as_posix()


def is_github_workflow(path: str) -> bool:
    normalized = _safe_path(path)
    return normalized.startswith(".github/workflows/") and normalized.lower().endswith(
        (".yml", ".yaml")
    )


def is_generated_path(path: str) -> bool:
    normalized = _safe_path(path)
    lowered = normalized.lower()
    parent = lowered.rsplit("/", 1)[0] if "/" in lowered else ""
    parent_parts = tuple(PurePosixPath(parent).parts)
    for marker in _GENERATED_DIRS:
        marker_parts = tuple(PurePosixPath(marker).parts)
        if any(
            parent_parts[index : index + len(marker_parts)] == marker_parts
            for index in range(len(parent_parts) - len(marker_parts) + 1)
        ):
            return True
    return lowered.endswith((".min.js", ".min.css", ".bundle.js", ".generated.cs"))


def classify_supply_chain_path(path: str) -> dict[str, str] | None:
    """Classify a tracked path without reading or interpreting repository code."""

    normalized = _safe_path(path)
    lowered = normalized.lower()
    name = lowered.rsplit("/", 1)[-1]
    if is_github_workflow(normalized) or name in {"action.yml", "action.yaml"}:
        return {"path": normalized, "kind": "ci-workflow", "ecosystem": "github-actions"}
    if name.startswith("requirements") and name.endswith((".txt", ".in")):
        return {"path": normalized, "kind": "manifest", "ecosystem": "python"}
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return {"path": normalized, "kind": "manifest", "ecosystem": "dotnet"}
    if name.endswith(".deps.json"):
        return {"path": normalized, "kind": "lockfile", "ecosystem": "dotnet"}
    if name.endswith(".cabal"):
        return {"path": normalized, "kind": "manifest", "ecosystem": "haskell"}
    if name in {"build", "build.bazel"} or name.endswith(".bzl"):
        return {"path": normalized, "kind": "build-config", "ecosystem": "bazel"}
    if name == ".terraform.lock.hcl":
        return {"path": normalized, "kind": "lockfile", "ecosystem": "generic"}
    if name.endswith(".tf"):
        return {"path": normalized, "kind": "build-config", "ecosystem": "generic"}
    if name.startswith(("dockerfile.", "containerfile.")):
        return {"path": normalized, "kind": "build-config", "ecosystem": "container"}
    if lowered.startswith((".github/attestations/", "provenance/", "attestations/")) or name.endswith(
        (".intoto.jsonl", ".spdx.json", ".cdx.json")
    ):
        return {"path": normalized, "kind": "provenance", "ecosystem": "generic"}
    exact = _EXACT_INPUTS.get(name)
    if exact:
        return {"path": normalized, "kind": exact[0], "ecosystem": exact[1]}
    if is_generated_path(normalized):
        return {"path": normalized, "kind": "generated-artifact", "ecosystem": "generic"}
    return None


def discover_supply_chain_inputs(paths: Iterable[str]) -> list[dict[str, str]]:
    """Return the exact deterministic classified subset of a tracked path list."""

    discovered: dict[str, dict[str, str]] = {}
    for raw in paths:
        item = classify_supply_chain_path(raw)
        if item is not None:
            discovered[item["path"]] = item
    return [discovered[path] for path in sorted(discovered)]


def parse_github_actions(path: str, content: bytes) -> list[dict[str, Any]]:
    """Parse exact ``uses:`` references from one bounded GitHub workflow blob."""

    if not is_github_workflow(path) and _safe_path(path).lower() not in {
        "action.yml",
        "action.yaml",
    }:
        return []
    if len(content) > _MAX_WORKFLOW_BYTES:
        raise SupplyChainProtocolError("workflow exceeds the bounded parser limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainProtocolError("workflow must be UTF-8") from exc
    results: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _USES_RE.match(line)
        if not match:
            if _USES_PREFIX_RE.match(line):
                raise SupplyChainProtocolError(
                    "workflow uses reference is dynamic or outside the closed parser"
                )
            continue
        locator = match.group("value")
        local = locator.startswith("./")
        docker = locator.startswith("docker://")
        reference = "local"
        if not local:
            reference = locator.rsplit("@", 1)[1] if "@" in locator else ""
        immutable = local or bool(_ACTION_SHA_RE.fullmatch(reference))
        if docker:
            immutable = bool(re.search(r"@sha256:[0-9a-f]{64}$", locator))
        results.append(
            {
                "path": _safe_path(path),
                "line": line_number,
                "locator": locator,
                "reference": reference,
                "referenceType": (
                    "local"
                    if local
                    else "digest"
                    if docker and immutable
                    else "commit"
                    if immutable
                    else "mutable"
                ),
                "immutable": immutable,
            }
        )
    return results


def parse_github_permissions(path: str, content: bytes) -> dict[str, Any]:
    """Parse top-level workflow permissions using a closed conservative subset."""

    if not is_github_workflow(path):
        return {"path": _safe_path(path), "mode": "not-applicable", "scopes": {}, "writeScopes": []}
    if len(content) > _MAX_WORKFLOW_BYTES:
        raise SupplyChainProtocolError("workflow exceeds the bounded parser limit")
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SupplyChainProtocolError("workflow must be UTF-8") from exc
    top_level = [
        (index, match)
        for index, line in enumerate(lines)
        if (match := _PERMISSIONS_RE.match(line)) is not None
        and len(match.group("indent")) == 0
    ]
    if len(top_level) > 1:
        raise SupplyChainProtocolError("workflow contains duplicate top-level permissions")
    for index, match in top_level:
        scalar = match.group("value").strip().strip("'\"")
        if scalar:
            if scalar == "read-all":
                return {"path": _safe_path(path), "mode": "explicit-read-all", "scopes": {}, "writeScopes": []}
            if scalar in {"{}", "none"}:
                return {"path": _safe_path(path), "mode": "explicit-none", "scopes": {}, "writeScopes": []}
            if scalar == "write-all":
                return {"path": _safe_path(path), "mode": "explicit-write-all", "scopes": {}, "writeScopes": ["*"]}
            return {"path": _safe_path(path), "mode": "unsupported", "scopes": {}, "writeScopes": []}
        scopes: dict[str, str] = {}
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip(" ")) == 0:
                break
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            item = _PERMISSION_ITEM_RE.match(candidate)
            if item is None:
                return {"path": _safe_path(path), "mode": "unsupported", "scopes": {}, "writeScopes": []}
            if item.group("scope") in scopes:
                raise SupplyChainProtocolError(
                    "workflow contains duplicate top-level permission scope"
                )
            scopes[item.group("scope")] = item.group("value")
        return {
            "path": _safe_path(path),
            "mode": "explicit-mapping",
            "scopes": dict(sorted(scopes.items())),
            "writeScopes": sorted(scope for scope, value in scopes.items() if value == "write"),
        }
    return {"path": _safe_path(path), "mode": "implicit", "scopes": {}, "writeScopes": []}


__all__ = [
    "DEPENDENCY_INVENTORY_SCHEMA_VERSION",
    "SUPPLY_CHAIN_REPORT_SCHEMA_VERSION",
    "SupplyChainProtocolError",
    "classify_supply_chain_path",
    "discover_supply_chain_inputs",
    "is_generated_path",
    "is_github_workflow",
    "parse_github_actions",
    "parse_github_permissions",
]
