#!/usr/bin/env python3
"""Route source-checkout installs through JStack's transactional installer."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional


SOURCE_DIR = Path(__file__).resolve().parent
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_RELEASE_LAYOUT_FILES = (
    "scripts/install.py",
    "scripts/check_product_boundaries.py",
    "plugin/.codex-plugin/plugin.json",
    "plugins/j-stack-dev/.codex-plugin/plugin.json",
    "plugins/jstack-audit/.codex-plugin/plugin.json",
    "plugins/jstack-evidence-builder/.codex-plugin/plugin.json",
    "plugins/jstack-full-team/.codex-plugin/plugin.json",
    "plugins/jstack-loop/.codex-plugin/plugin.json",
    "plugins/jstack-subagents/.codex-plugin/plugin.json",
    "prompts/j-stack-dev.md",
    "prompts/jstack-audit.md",
    "prompts/jstack-evidence-builder.md",
    "prompts/jstack-full-team.md",
    "prompts/jstack-loop.md",
    "prompts/jstack-subagents.md",
    "skills/jstack-dev/SKILL.md",
    "skills/jstack-audit/SKILL.md",
    "skills/jstack-evidence-builder/SKILL.md",
    "skills/jstack-loop/SKILL.md",
    "skills/product-ui-design/SKILL.md",
    "mcp/jstack/ui/evidence.py",
    "mcp/jstack/ui/reference.py",
    "mcp/jstack/project_intelligence/catalog.v1.json",
    "mcp/jstack/project_intelligence/protocol.py",
    "mcp/jstack/schemas/project-intelligence-index.v1.schema.json",
    "mcp/jstack/schemas/project-intelligence-query.v1.schema.json",
    "mcp/jstack/schemas/project-intelligence-impact.v1.schema.json",
    "mcp/jstack/schemas/project-intelligence-refresh.v1.schema.json",
    "mcp/jstack/schemas/project-intelligence-finalization.v1.schema.json",
    "mcp/jstack/schemas/ui-evidence.v1.schema.json",
    "mcp/jstack/schemas/ui-contract.v2.schema.json",
    "mcp/jstack/schemas/ui-objective-result.v1.schema.json",
    "mcp/jstack/schemas/ui-product-observation.v1.schema.json",
    "mcp/jstack/schemas/ui-reference-analysis.v1.schema.json",
    "mcp/jstack/schemas/ui-reference-contract.v1.schema.json",
    "mcp/jstack/schemas/ui-reference-bundle.v1.schema.json",
    "mastery/curriculum.v1.json",
    "mastery/audit-curriculum.v1.json",
    "mastery/loop-curriculum.v1.json",
)


def _complete_release_layout(repository_root: Path) -> bool:
    """Recognize a complete release checkout, not an installed MCP subtree."""
    try:
        version_path = repository_root / "VERSION"
        if not version_path.is_file() or version_path.stat().st_size > 128:
            return False
        version = version_path.read_text(encoding="utf-8").strip()
        if not _VERSION_PATTERN.fullmatch(version):
            return False
        if any(not (repository_root / relative).is_file() for relative in _RELEASE_LAYOUT_FILES):
            return False
        for relative in (
            "plugin/.codex-plugin/plugin.json",
            "plugins/j-stack-dev/.codex-plugin/plugin.json",
            "plugins/jstack-audit/.codex-plugin/plugin.json",
            "plugins/jstack-evidence-builder/.codex-plugin/plugin.json",
            "plugins/jstack-full-team/.codex-plugin/plugin.json",
            "plugins/jstack-loop/.codex-plugin/plugin.json",
            "plugins/jstack-subagents/.codex-plugin/plugin.json",
        ):
            manifest_path = repository_root / relative
            if manifest_path.stat().st_size > 64_000:
                return False
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or manifest.get("version") != version:
                return False
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return True


def repository_installer() -> Optional[Path]:
    """Return the trusted checkout installer, never an installed MCP neighbor."""
    repository_root = SOURCE_DIR.parents[1]
    installer = repository_root / "scripts" / "install.py"
    if _complete_release_layout(repository_root):
        return installer
    return None


def main(argv: Optional[list[str]] = None) -> int:
    installer = repository_installer()
    if installer is None:
        print(
            "This installed MCP copy is not a standalone updater. "
            "Download or clone an immutable JStack release and run its "
            "top-level scripts/install.py so every payload and config change "
            "uses the transactional installer.",
            file=sys.stderr,
        )
        return 2
    repository_root = installer.parent.parent
    forwarded = list(sys.argv[1:]) if argv is None else list(argv)
    if any(argument.startswith("--repo") for argument in forwarded):
        print(
            "The MCP compatibility router owns --repo-root; pass installer options only.",
            file=sys.stderr,
        )
        return 2
    command = [
        sys.executable,
        str(installer),
        "--repo-root",
        str(repository_root),
        *forwarded,
    ]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
