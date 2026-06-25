#!/usr/bin/env python3
"""Install gstack-dev command, skill, and MCP server into Codex."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
from pathlib import Path


def copytree_replace(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))


def remove_existing_gstack_block(config: str) -> str:
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


def mcp_block(install_dir: Path) -> str:
    is_windows = platform.system().lower().startswith("win")
    command = "python" if is_windows else "python3"
    gstack_root = Path.home() / ".gstack" / "repos" / "gstack"
    if is_windows:
        path = f"{gstack_root / 'bin'};C:/Windows/System32;C:/Windows;C:/Windows/System32/WindowsPowerShell/v1.0"
    else:
        path = f"{gstack_root / 'bin'}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    server = (install_dir / "gstack_mcp_server.py").as_posix()
    return f"""
[mcp_servers.gstack]
command = "{command}"
args = ["{server}"]
startup_timeout_sec = 30.0
tool_timeout_sec = 300.0

[mcp_servers.gstack.env]
GSTACK_ROOT = "{gstack_root.as_posix()}"
PATH = "{path}"
""".strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    args = parser.parse_args()

    repo_root = Path(args.repo_root).expanduser().resolve()
    codex_home = Path(args.codex_home).expanduser().resolve()
    if not repo_root.exists():
        raise SystemExit(f"Repo root not found: {repo_root}")

    prompts_dir = codex_home / "prompts"
    skills_dir = codex_home / "skills" / "gstack-dev"
    mcp_dir = codex_home / "mcp" / "gstack"
    config_path = codex_home / "config.toml"

    prompts_dir.mkdir(parents=True, exist_ok=True)
    (codex_home / "skills").mkdir(parents=True, exist_ok=True)
    (codex_home / "mcp").mkdir(parents=True, exist_ok=True)

    shutil.copy2(repo_root / "prompts" / "gstack-dev.md", prompts_dir / "gstack-dev.md")
    copytree_replace(repo_root / "skills" / "gstack-dev", skills_dir)
    copytree_replace(repo_root / "mcp" / "gstack", mcp_dir)

    if not config_path.exists():
        config_path.write_text("", encoding="utf-8")
    original = config_path.read_text(encoding="utf-8")
    backup = config_path.with_suffix(".toml.gstack-dev-backup")
    backup.write_text(original, encoding="utf-8")
    updated = remove_existing_gstack_block(original)
    updated = updated.rstrip() + "\n\n" + mcp_block(mcp_dir) + "\n"
    config_path.write_text(updated, encoding="utf-8")

    print(f"Installed /gstack-dev prompt to {prompts_dir / 'gstack-dev.md'}")
    print(f"Installed gstack-dev skill to {skills_dir}")
    print(f"Installed gstack MCP to {mcp_dir}")
    print(f"Updated Codex config: {config_path}")
    print(f"Backup written: {backup}")
    print("Restart Codex or open a new thread for command and MCP changes to load.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
