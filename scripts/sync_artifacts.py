#!/usr/bin/env python3
"""Synchronize and verify JStack's generated plugin artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
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
    ROOT / "skills" / "jstack-dev" / "SKILL.md": [ROOT / "plugin" / "skills" / "jstack-dev" / "SKILL.md"],
    ROOT / "mastery" / "curriculum.v1.json": [
        ROOT / "mcp" / "jstack" / "mastery" / "curriculum.v1.json",
        ROOT / "plugin" / "mcp" / "mastery" / "curriculum.v1.json",
    ],
}

for source in sorted((ROOT / "mcp" / "jstack" / "templates").glob("*")):
    if source.is_file():
        FILE_MAP[source] = [ROOT / "plugin" / "mcp" / "templates" / source.name]

for source in sorted((ROOT / "skills" / "jstack-dev" / "references").glob("*.md")):
    FILE_MAP[source] = [ROOT / "plugin" / "skills" / "jstack-dev" / "references" / source.name]
FILE_MAP[ROOT / "skills" / "jstack-dev" / "references" / "mastery-system.md"].append(
    ROOT / "docs" / "mastery-system.md"
)


def normalized_source(path: Path) -> bytes:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if path.suffix.lower() in {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".mjs"}:
        data = data.replace(b"\r\n", b"\n")
    return data


def tracked_text_files() -> list[Path]:
    excluded = {".git", "__pycache__", ".pytest_cache"}
    suffixes = {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".mjs", ".txt"}
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes and not any(part in excluded for part in path.parts)
    ]


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


def check_json(errors: list[str]) -> None:
    for path in ROOT.rglob("*.json"):
        if ".git" in path.parts:
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
        # Normalize canonical text too, removing historical BOM/CRLF drift.
        for path in tracked_text_files():
            path.write_bytes(normalized_source(path))

    for path in tracked_text_files():
        if path.read_bytes().startswith(b"\xef\xbb\xbf"):
            errors.append(f"UTF-8 BOM is not allowed: {path.relative_to(ROOT)}")
    check_json(errors)
    validate_versions(errors)

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("JStack artifacts are synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
