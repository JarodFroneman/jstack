#!/usr/bin/env python3
"""Install JStack commands, skills, and MCP server into Codex."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any, Optional


PROMPTS = (
    "j-stack-dev.md",
    "jstack-subagents.md",
    "jstack-full-team.md",
    "jstack-audit.md",
    "jstack-loop.md",
)


def copytree_replace(source: Path, target: Path) -> None:
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


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.jstack-{uuid.uuid4().hex}"
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(mode)
    os.replace(temporary, path)


def archive_existing(path: Path, archive_root: Path) -> Optional[Path]:
    if not path.exists():
        return None
    archive_root.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    target = archive_root / f"{path.name}-{stamp}"
    shutil.move(str(path), str(target))
    return target


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


class InstallTransaction:
    """Stage a complete install and restore every target if any phase fails."""

    def __init__(self, codex_home: Path) -> None:
        self.root = codex_home / f".jstack-install-{uuid.uuid4().hex}"
        self.stage_root = self.root / "stage"
        self.backup_root = self.root / "backup"
        self.stage_root.mkdir(parents=True)
        self.backup_root.mkdir(parents=True)
        self.snapshots: list[tuple[Path, Optional[Path]]] = []
        self.archives: list[tuple[Path, Path]] = []

    def stage_tree(self, name: str, source: Path) -> Path:
        target = self.stage_root / name
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
        )
        return target

    def snapshot(self, target: Path) -> None:
        if target.is_symlink():
            raise RuntimeError(f"Refusing to replace symlink install target: {target}")
        backup: Optional[Path] = None
        if target.exists():
            backup = self.backup_root / f"{len(self.snapshots):04d}-{target.name}"
            if target.is_dir():
                shutil.copytree(target, backup, symlinks=True)
            else:
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
        self.snapshots.append((target, backup))

    def archive(self, source: Path, archive_root: Path) -> Optional[Path]:
        if not source.exists():
            return None
        if source.is_symlink():
            raise RuntimeError(f"Refusing to archive symlink install target: {source}")
        archive_root.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        target = archive_root / f"{source.name}-{stamp}-{uuid.uuid4().hex[:8]}"
        shutil.move(str(source), str(target))
        self.archives.append((source, target))
        return target

    def rollback(self) -> None:
        errors: list[str] = []
        for source, archived in reversed(self.archives):
            try:
                remove_path(source)
                source.parent.mkdir(parents=True, exist_ok=True)
                if archived.exists():
                    os.replace(archived, source)
            except Exception as exc:  # pragma: no cover - catastrophic filesystem failure
                errors.append(f"archive restore {source}: {exc}")
        for target, backup in reversed(self.snapshots):
            try:
                remove_path(target)
                if backup is not None and backup.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(backup, target)
            except Exception as exc:  # pragma: no cover - catastrophic filesystem failure
                errors.append(f"target restore {target}: {exc}")
        shutil.rmtree(self.root, ignore_errors=True)
        if errors:
            raise RuntimeError("JStack install rollback was incomplete: " + "; ".join(errors))

    def commit(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def remove_existing_stack_blocks(config: str) -> str:
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


def mcp_block(install_dir: Path) -> str:
    command = Path(sys.executable).as_posix()
    server = (install_dir / "jstack_mcp_server.py").as_posix()
    return f"""
[mcp_servers.jstack]
command = {json.dumps(command)}
args = [{json.dumps(server)}]
startup_timeout_sec = 30.0
tool_timeout_sec = 300.0
""".strip()


def install(repo_root: Path, codex_home: Path) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve()
    codex_home = codex_home.expanduser().resolve()
    if not repo_root.exists():
        raise RuntimeError(f"Repo root not found: {repo_root}")

    prompts_dir = codex_home / "prompts"
    skills_root = codex_home / "skills"
    skill_dir = skills_root / "jstack-dev"
    audit_skill_dir = skills_root / "jstack-audit"
    loop_skill_dir = skills_root / "jstack-loop"
    mcp_root = codex_home / "mcp"
    mcp_dir = mcp_root / "jstack"
    config_path = codex_home / "config.toml"

    transaction = InstallTransaction(codex_home)
    prompt_contents = {
        prompt: (repo_root / "prompts" / prompt).read_text(encoding="utf-8")
        for prompt in PROMPTS
    }
    staged_skill = transaction.stage_tree("jstack-dev-skill", repo_root / "skills" / "jstack-dev")
    staged_audit_skill = transaction.stage_tree(
        "jstack-audit-skill", repo_root / "skills" / "jstack-audit"
    )
    staged_loop_skill = transaction.stage_tree(
        "jstack-loop-skill", repo_root / "skills" / "jstack-loop"
    )
    staged_mcp = transaction.stage_tree("jstack-mcp", repo_root / "mcp" / "jstack")
    staged_mastery = staged_mcp / "mastery"
    remove_path(staged_mastery)
    shutil.copytree(repo_root / "mastery", staged_mastery)

    original = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    backup = config_path.with_suffix(".toml.jstack-backup")
    updated = remove_existing_stack_blocks(original)
    updated = updated.rstrip() + "\n\n" + mcp_block(mcp_dir) + "\n"

    install_targets = [
        *(prompts_dir / prompt for prompt in PROMPTS),
        skill_dir,
        audit_skill_dir,
        loop_skill_dir,
        mcp_dir,
        backup,
        config_path,
    ]
    archived_prompt = None
    archived_skill = None
    try:
        for target in install_targets:
            transaction.snapshot(target)
        archived_prompt = transaction.archive(
            prompts_dir / "gstack-dev.md", codex_home / "prompts-disabled"
        )
        archived_skill = transaction.archive(
            skills_root / "gstack-dev", codex_home / "skills-disabled"
        )
        for prompt in PROMPTS:
            atomic_write_text(prompts_dir / prompt, prompt_contents[prompt], mode=0o644)
        copytree_replace(staged_skill, skill_dir)
        copytree_replace(staged_audit_skill, audit_skill_dir)
        copytree_replace(staged_loop_skill, loop_skill_dir)
        copytree_replace(staged_mcp, mcp_dir)
        atomic_write_text(backup, original)
        atomic_write_text(config_path, updated)
    except Exception:
        transaction.rollback()
        raise
    transaction.commit()

    return {
        "promptsDir": prompts_dir,
        "skillDir": skill_dir,
        "auditSkillDir": audit_skill_dir,
        "loopSkillDir": loop_skill_dir,
        "mcpDir": mcp_dir,
        "configPath": config_path,
        "backup": backup,
        "archivedPrompt": archived_prompt,
        "archivedSkill": archived_skill,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    codex_home = Path(args.codex_home)
    outcome = install(repo_root, codex_home)
    prompts_dir = outcome["promptsDir"]
    skill_dir = outcome["skillDir"]
    audit_skill_dir = outcome["auditSkillDir"]
    loop_skill_dir = outcome["loopSkillDir"]
    mcp_dir = outcome["mcpDir"]
    config_path = outcome["configPath"]
    backup = outcome["backup"]
    archived_prompt = outcome["archivedPrompt"]
    archived_skill = outcome["archivedSkill"]

    print("Installed JStack prompts:")
    for prompt in PROMPTS:
        print(f"  - {prompts_dir / prompt}")
    print(f"Installed jstack-dev skill to {skill_dir}")
    print(f"Installed jstack-audit skill to {audit_skill_dir}")
    print(f"Installed jstack-loop skill to {loop_skill_dir}")
    print(f"Installed JStack MCP to {mcp_dir}")
    print(f"Updated Codex config: {config_path}")
    print(f"Backup written: {backup}")
    if archived_prompt:
        print(f"Archived old /gstack-dev prompt: {archived_prompt}")
    if archived_skill:
        print(f"Archived old gstack-dev skill: {archived_skill}")
    print("Restart Codex or open a new thread for command and MCP changes to load.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
