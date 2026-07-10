#!/usr/bin/env python3
"""Install the local jstack MCP server into Codex config.toml."""

from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
CODEX_HOME = Path.home() / ".codex"
INSTALL_DIR = CODEX_HOME / "mcp" / "jstack"
CONFIG_PATH = CODEX_HOME / "config.toml"


def remove_existing_block(config: str) -> str:
    lines = config.splitlines()
    output: list[str] = []
    skip = False
    for line in lines:
        stripped = line.strip()
        if stripped in {"[mcp_servers.gstack]", "[mcp_servers.jstack]"}:
            skip = True
            continue
        if skip and stripped.startswith("[") and stripped not in {"[mcp_servers.gstack.env]", "[mcp_servers.jstack.env]"}:
            skip = False
        if skip:
            continue
        output.append(line)
    return "\n".join(output).rstrip() + "\n"


def mcp_block() -> str:
    command = Path(sys.executable).as_posix()
    return f"""
[mcp_servers.jstack]
command = {json.dumps(command)}
args = [{json.dumps((INSTALL_DIR / "jstack_mcp_server.py").as_posix())}]
startup_timeout_sec = 30.0
tool_timeout_sec = 300.0
""".strip()


def atomic_write_text(path: Path, content: str) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.jstack-{uuid.uuid4().hex}"
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def atomic_copytree(source: Path, target: Path) -> None:
    if target.is_symlink():
        raise RuntimeError(f"Refusing to replace symlink install target: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.parent / f".{target.name}.jstack-stage-{uuid.uuid4().hex}"
    backup = target.parent / f".{target.name}.jstack-rollback-{uuid.uuid4().hex}"
    shutil.copytree(source, staging, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    replaced = False
    try:
        if target.exists():
            os.replace(target, backup)
            replaced = True
        os.replace(staging, target)
        if backup.exists():
            shutil.rmtree(backup)
    except Exception:
        if target.exists() and not target.is_symlink():
            shutil.rmtree(target)
        if replaced and backup.exists():
            os.replace(backup, target)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> int:
    CODEX_HOME.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        atomic_write_text(CONFIG_PATH, "")
    if INSTALL_DIR.resolve() != SOURCE_DIR.resolve():
        atomic_copytree(SOURCE_DIR, INSTALL_DIR)

    original = CONFIG_PATH.read_text(encoding="utf-8")
    backup = CONFIG_PATH.with_suffix(".toml.jstack-mcp-backup")
    atomic_write_text(backup, original)

    updated = remove_existing_block(original)
    updated = updated.rstrip() + "\n\n" + mcp_block() + "\n"
    atomic_write_text(CONFIG_PATH, updated)
    print(f"Installed jstack MCP server to {INSTALL_DIR}")
    print(f"Updated Codex config: {CONFIG_PATH}")
    print(f"Backup written: {backup}")
    print("Restart Codex or start a new thread for the MCP tools to appear.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
