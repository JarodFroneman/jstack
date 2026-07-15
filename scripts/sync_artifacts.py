#!/usr/bin/env python3
"""Synchronize and verify JStack's generated plugin artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

FILE_MAP = {
    ROOT / "mcp" / "jstack" / "jstack_mcp_server.py": [
        ROOT / "plugin" / "mcp" / "jstack_mcp_server.py",
    ],
    ROOT / "prompts" / "j-stack-dev.md": [ROOT / "plugin" / "commands" / "j-stack-dev.md"],
    ROOT / "prompts" / "jstack-subagents.md": [ROOT / "plugin" / "commands" / "jstack-subagents.md"],
    ROOT / "prompts" / "jstack-full-team.md": [ROOT / "plugin" / "commands" / "jstack-full-team.md"],
    ROOT / "prompts" / "jstack-audit.md": [ROOT / "plugin" / "commands" / "jstack-audit.md"],
    ROOT / "prompts" / "jstack-loop.md": [ROOT / "plugin" / "commands" / "jstack-loop.md"],
    ROOT / "skills" / "jstack-dev" / "SKILL.md": [ROOT / "plugin" / "skills" / "jstack-dev" / "SKILL.md"],
    ROOT / "mastery" / "curriculum.v1.json": [
        ROOT / "mcp" / "jstack" / "mastery" / "curriculum.v1.json",
        ROOT / "plugin" / "mcp" / "mastery" / "curriculum.v1.json",
    ],
    ROOT / "mastery" / "audit-curriculum.v1.json": [
        ROOT / "mcp" / "jstack" / "mastery" / "audit-curriculum.v1.json",
        ROOT / "plugin" / "mcp" / "mastery" / "audit-curriculum.v1.json",
    ],
    ROOT / "mastery" / "loop-curriculum.v1.json": [
        ROOT / "mcp" / "jstack" / "mastery" / "loop-curriculum.v1.json",
        ROOT / "plugin" / "mcp" / "mastery" / "loop-curriculum.v1.json",
    ],
}

for source in sorted((ROOT / "tests" / "fixtures" / "audit").glob("*.json")):
    FILE_MAP[source] = [
        ROOT / "mcp" / "jstack" / "audit" / "benchmark-corpus" / source.name,
        ROOT / "plugin" / "mcp" / "audit" / "benchmark-corpus" / source.name,
    ]

for source in sorted((ROOT / "mcp" / "jstack" / "audit").rglob("*")):
    if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
        relative = source.relative_to(ROOT / "mcp" / "jstack" / "audit")
        FILE_MAP[source] = [ROOT / "plugin" / "mcp" / "audit" / relative]

for source in sorted((ROOT / "mcp" / "jstack" / "loop").rglob("*")):
    if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
        relative = source.relative_to(ROOT / "mcp" / "jstack" / "loop")
        FILE_MAP[source] = [ROOT / "plugin" / "mcp" / "loop" / relative]

for source in sorted((ROOT / "mcp" / "jstack" / "schemas").glob("*.json")):
    FILE_MAP[source] = [ROOT / "plugin" / "mcp" / "schemas" / source.name]

for source in sorted((ROOT / "skills" / "jstack-audit").rglob("*")):
    if source.is_file():
        relative = source.relative_to(ROOT / "skills" / "jstack-audit")
        FILE_MAP[source] = [
            ROOT / "plugin" / "skills" / "jstack-audit" / relative,
            ROOT / "plugins" / "jstack-audit" / "skills" / "jstack-audit" / relative,
        ]

for source in sorted((ROOT / "skills" / "jstack-loop").rglob("*")):
    if source.is_file():
        relative = source.relative_to(ROOT / "skills" / "jstack-loop")
        FILE_MAP[source] = [
            ROOT / "plugin" / "skills" / "jstack-loop" / relative,
            ROOT / "plugins" / "jstack-loop" / "skills" / "jstack-loop" / relative,
        ]
FILE_MAP[ROOT / "skills" / "jstack-loop" / "references" / "mastery-system.md"].append(
    ROOT / "docs" / "loop-mastery-system.md"
)

for source in sorted((ROOT / "mcp" / "jstack" / "templates").glob("*")):
    if source.is_file():
        FILE_MAP[source] = [ROOT / "plugin" / "mcp" / "templates" / source.name]

for source in sorted((ROOT / "skills" / "jstack-dev" / "references").glob("*.md")):
    FILE_MAP[source] = [ROOT / "plugin" / "skills" / "jstack-dev" / "references" / source.name]
FILE_MAP[ROOT / "skills" / "jstack-dev" / "references" / "mastery-system.md"].append(
    ROOT / "docs" / "mastery-system.md"
)

TREE_MIRRORS = (
    (ROOT / "mcp" / "jstack" / "audit", ROOT / "plugin" / "mcp" / "audit"),
    (ROOT / "mcp" / "jstack" / "loop", ROOT / "plugin" / "mcp" / "loop"),
    (ROOT / "mcp" / "jstack" / "schemas", ROOT / "plugin" / "mcp" / "schemas"),
    (ROOT / "skills" / "jstack-audit", ROOT / "plugin" / "skills" / "jstack-audit"),
    (
        ROOT / "skills" / "jstack-audit",
        ROOT / "plugins" / "jstack-audit" / "skills" / "jstack-audit",
    ),
    (ROOT / "skills" / "jstack-loop", ROOT / "plugin" / "skills" / "jstack-loop"),
    (
        ROOT / "skills" / "jstack-loop",
        ROOT / "plugins" / "jstack-loop" / "skills" / "jstack-loop",
    ),
)


def normalized_source(path: Path) -> bytes:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if path.suffix.lower() in {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".mjs"}:
        data = data.replace(b"\r\n", b"\n")
    return data


def git_tracked_files() -> set[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return set()
    paths = set()
    for raw in result.stdout.split(b"\0"):
        if raw:
            paths.add(ROOT / raw.decode("utf-8", errors="strict"))
    return paths


def managed_text_files() -> list[Path]:
    suffixes = {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".mjs", ".txt"}
    managed = git_tracked_files()
    managed.update(FILE_MAP)
    managed.update(target for targets in FILE_MAP.values() for target in targets)
    managed.update(ROOT.glob("plugins/*/.codex-plugin/plugin.json"))
    managed.add(ROOT / "plugin" / ".codex-plugin" / "plugin.json")
    return sorted(
        path for path in managed if path.is_file() and path.suffix.lower() in suffixes
    )


def tree_inventory(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def validate_tree_mirrors(errors: list[str], write: bool) -> None:
    for source, target in TREE_MIRRORS:
        expected = tree_inventory(source)
        actual = tree_inventory(target)
        extras = sorted(actual - expected)
        if write:
            for relative in extras:
                (target / relative).unlink()
        elif extras:
            try:
                target_label = target.relative_to(ROOT)
            except ValueError:
                target_label = target
            errors.append(
                "Stale generated artifacts under %s: %s"
                % (target_label, ", ".join(extras))
            )


def validate_versions(errors: list[str]) -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    server_text = (ROOT / "mcp" / "jstack" / "jstack_mcp_server.py").read_text(encoding="utf-8")
    if f'SERVER_VERSION = "{version}"' not in server_text:
        errors.append(f"MCP SERVER_VERSION does not match VERSION ({version}).")
    manifests = [ROOT / "plugin" / ".codex-plugin" / "plugin.json", *ROOT.glob("plugins/*/.codex-plugin/plugin.json")]
    for manifest in manifests:
        data = json.loads(manifest.read_text(encoding="utf-8-sig"))
        base_version = str(data.get("version", "")).split("+", 1)[0]
        if base_version != version:
            errors.append(f"Manifest version drift: {manifest.relative_to(ROOT)} has {data.get('version')}, expected {version} base.")


def check_json(errors: list[str], paths: list[Path]) -> None:
    for path in paths:
        if path.suffix.lower() != ".json":
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"Invalid BOM-free JSON: {path.relative_to(ROOT)}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    errors: list[str] = []

    for source, targets in FILE_MAP.items():
        data = normalized_source(source)
        for target in targets:
            if args.write:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            elif not target.exists() or normalized_source(target) != data:
                errors.append(f"Generated artifact drift: {target.relative_to(ROOT)} != {source.relative_to(ROOT)}")

    if args.write:
        # Normalize only Git-tracked or explicitly declared canonical/generated files.
        for path in managed_text_files():
            path.write_bytes(normalized_source(path))

    validate_tree_mirrors(errors, args.write)
    managed_files = managed_text_files()
    for path in managed_files:
        if path.read_bytes().startswith(b"\xef\xbb\xbf"):
            errors.append(f"UTF-8 BOM is not allowed: {path.relative_to(ROOT)}")
    check_json(errors, managed_files)
    validate_versions(errors)

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("JStack artifacts are synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
