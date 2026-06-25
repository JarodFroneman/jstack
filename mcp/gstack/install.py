#!/usr/bin/env python3
"""Install the local gstack MCP server into Codex config.toml."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
CODEX_HOME = Path.home() / ".codex"
INSTALL_DIR = CODEX_HOME / "mcp" / "gstack"
CONFIG_PATH = CODEX_HOME / "config.toml"


def remove_existing_block(config: str) -> str:
    lines = config.splitlines()
    output: list[str] = []
    skip = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[mcp_servers.gstack]":
            skip = True
            continue
        if skip and stripped.startswith("[") and stripped != "[mcp_servers.gstack.env]":
            skip = False
        if skip:
            continue
        output.append(line)
    return "\n".join(output).rstrip() + "\n"


def mcp_block() -> str:
    is_windows = platform.system().lower().startswith("win")
    command = "python" if is_windows else "python3"
    gstack_root = Path.home() / ".gstack" / "repos" / "gstack"
    if is_windows:
        path = f"{gstack_root / 'bin'};C:/Windows/System32;C:/Windows;C:/Windows/System32/WindowsPowerShell/v1.0"
    else:
        path = f"{gstack_root / 'bin'}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    return f"""
[mcp_servers.gstack]
command = "{command}"
args = ["{(INSTALL_DIR / "gstack_mcp_server.py").as_posix()}"]
startup_timeout_sec = 30.0
tool_timeout_sec = 300.0

[mcp_servers.gstack.env]
GSTACK_ROOT = "{gstack_root.as_posix()}"
PATH = "{path}"
""".strip()


def main() -> int:
    if not CONFIG_PATH.exists():
        raise SystemExit(f"Codex config not found: {CONFIG_PATH}")
    if INSTALL_DIR.exists() and INSTALL_DIR.resolve() != SOURCE_DIR.resolve():
        shutil.rmtree(INSTALL_DIR)
        shutil.copytree(SOURCE_DIR, INSTALL_DIR, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))

    original = CONFIG_PATH.read_text(encoding="utf-8")
    backup = CONFIG_PATH.with_suffix(".toml.gstack-mcp-backup")
    backup.write_text(original, encoding="utf-8")

    updated = remove_existing_block(original)
    updated = updated.rstrip() + "\n\n" + mcp_block() + "\n"
    CONFIG_PATH.write_text(updated, encoding="utf-8")
    print(f"Installed gstack MCP server to {INSTALL_DIR}")
    print(f"Updated Codex config: {CONFIG_PATH}")
    print(f"Backup written: {backup}")
    print("Restart Codex or start a new thread for the MCP tools to appear.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
