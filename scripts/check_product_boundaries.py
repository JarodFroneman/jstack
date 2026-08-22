#!/usr/bin/env python3
"""Enforce JStack's permanent anti-bloat and no-authority boundaries."""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {
    "j-stack-dev.md",
    "jstack-audit.md",
    "jstack-evidence-builder.md",
    "jstack-full-team.md",
    "jstack-loop.md",
    "jstack-subagents.md",
}
PLUGIN_NAMES = {
    "j-stack-dev", "jstack-audit", "jstack-evidence-builder",
    "jstack-full-team", "jstack-loop", "jstack-subagents",
}
ROLES = {
    "lead",
    "architect",
    "investigator",
    "builder",
    "reviewer",
    "qa",
    "security",
    "devops",
    "product",
    "quant",
    "docs",
}
CAPABILITIES = {
    "evidence-led-handoff",
    "minimal-change",
    "codebase-orientation",
    "developer-tooling",
    "agent-systems",
    "workflow-architecture",
    "api-platform",
    "database-reliability",
    "incident-reliability",
    "identity-access",
    "accessibility-assurance",
    "performance-engineering",
    "ai-code-security",
    "compliance-assurance",
    "web-launch-assurance",
    "email-deliverability",
    "product-observability",
    "privacy-legal-evidence",
}
ADDITIVE_CANONICAL_TOOLS = {
    "jstack_ui_contract",
    "jstack_ui_finalize",
    "jstack_ui_reference_contract",
    "jstack_ui_reference_finalize",
    "jstack_ui_motion_spec",
    "jstack_prompt_compile",
}
CONTRACT_FIXTURE = ROOT / "tests" / "fixtures" / "contracts" / "v0.10.0-alpha.9.json"
FROZEN_CANONICAL_TOOL_COUNT = 52
FROZEN_ALIAS_COUNT = 52
LIVE_CANONICAL_TOOL_COUNT = 58
CORE_LOCAL_IMPORTS = {
    "audit",
    "capabilities",
    "context_readiness",
    "launch",
    "loop",
    "program",
    "prompt_compiler",
    "ui",
}
CORE_STDLIB_IMPORTS = {
    "__future__",
    "argparse",
    "base64",
    "collections",
    "datetime",
    "fnmatch",
    "functools",
    "hashlib",
    "hmac",
    "html",
    "json",
    "math",
    "os",
    "pathlib",
    "platform",
    "re",
    "secrets",
    "shlex",
    "shutil",
    "signal",
    "stat",
    "struct",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "time",
    "traceback",
    "typing",
    "urllib",
    "uuid",
    "zlib",
}
NETWORK_IMPORTS = {"aiohttp", "ftplib", "http", "httpx", "requests", "smtplib", "socket", "urllib3"}
VENDOR_IMPORTS = {"anthropic", "azure", "boto3", "github", "gitlab", "google", "openai", "semgrep", "snyk", "trivy"}
PROOF_MAINTAINER_ROOT = ROOT / "tools" / "proof_plane"


def _load_module(name: str, path: Path) -> Any:
    sys.path.insert(0, str(ROOT / "mcp" / "jstack"))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _absolute_import_roots(root: Path) -> set[str]:
    names: set[str] = set()
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".", 1)[0])
    return names


def _evals_forbidden_actions() -> list[str]:
    errors: list[str] = []
    for path in (ROOT / "evals").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = ""
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        if root in NETWORK_IMPORTS | VENDOR_IMPORTS | {"subprocess"}:
                            errors.append("Proof Plane imports forbidden execution/network module %s in %s" % (root, path.relative_to(ROOT)))
                elif node.level == 0 and node.module:
                    module = node.module.split(".", 1)[0]
                    if module in NETWORK_IMPORTS | VENDOR_IMPORTS | {"subprocess"}:
                        errors.append("Proof Plane imports forbidden execution/network module %s in %s" % (module, path.relative_to(ROOT)))
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Attribute) and function.attr in {"write_bytes", "write_text", "unlink", "rename", "mkdir", "rmdir"}:
                    errors.append("Proof Plane contains a filesystem mutation call %s in %s" % (function.attr, path.relative_to(ROOT)))
                if isinstance(function, ast.Name) and function.id == "open" and len(node.args) >= 2:
                    mode = node.args[1]
                    if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in "wax+"):
                        errors.append("Proof Plane opens a writable file in %s" % path.relative_to(ROOT))
    return errors


def check_boundaries() -> list[str]:
    errors: list[str] = []
    prompt_names = {path.name for path in (ROOT / "prompts").glob("*.md")}
    if prompt_names != COMMANDS:
        errors.append("JStack must expose exactly the six named command prompts")
    plugin_names = {path.name for path in (ROOT / "plugins").iterdir() if path.is_dir()}
    if plugin_names != PLUGIN_NAMES:
        errors.append("JStack must retain exactly the six dedicated command plugins")

    server = _load_module("jstack_boundary_server", ROOT / "mcp" / "jstack" / "jstack_mcp_server.py")
    canonical = {name for name in server.TOOLS if name.startswith("jstack_")}
    aliases = {name for name in server.TOOLS if name.startswith("gstack_")}
    fixture = json.loads(CONTRACT_FIXTURE.read_text(encoding="utf-8"))
    frozen_canonical = set(fixture["canonicalToolInputSchemaSha256"])
    frozen_aliases = set(fixture["legacyAliases"])
    expected_canonical = frozen_canonical | ADDITIVE_CANONICAL_TOOLS
    if len(frozen_canonical) != FROZEN_CANONICAL_TOOL_COUNT:
        errors.append("frozen canonical MCP snapshot must remain at 52 tools")
    if len(frozen_aliases) != FROZEN_ALIAS_COUNT:
        errors.append("frozen legacy MCP alias snapshot must remain at 52 tools")
    if len(canonical) != LIVE_CANONICAL_TOOL_COUNT or canonical != expected_canonical:
        errors.append(
            "canonical MCP tool inventory must be the frozen 52 plus exactly five Product Interface tools and the Prompt Compiler"
        )
    if len(aliases) != FROZEN_ALIAS_COUNT or aliases != frozen_aliases:
        errors.append("legacy MCP alias inventory must remain the exact frozen 52")
    if any(name.startswith("gstack_ui_") for name in aliases):
        errors.append("Product Interface System tools must not gain gstack aliases")
    for name in sorted(frozen_canonical):
        alias = "gstack_" + name[len("jstack_") :]
        if (
            alias not in aliases
            or name not in canonical
            or server.TOOLS[alias]["inputSchema"] != server.TOOLS[name]["inputSchema"]
            or server.TOOLS[alias]["handler"] is not server.TOOLS[name]["handler"]
        ):
            errors.append("legacy alias does not map exactly to %s" % name)

    capabilities = server.capability_core
    if set(capabilities.ROSTER_ROLE_IDS) != ROLES:
        errors.append("core role roster changed")
    catalog = capabilities.load_catalog()
    if {item["id"] for item in catalog["capabilities"]} != CAPABILITIES:
        errors.append("capability-pack inventory changed rather than being replaced deliberately")

    launch = server.launch_core
    launch_catalog = launch.load_catalog()
    if len(launch_catalog["controls"]) != 47 or len(launch_catalog["surfaces"]) != 22:
        errors.append("launch catalog boundary changed")

    imports = _absolute_import_roots(ROOT / "mcp" / "jstack")
    unknown_imports = imports - CORE_LOCAL_IMPORTS - CORE_STDLIB_IMPORTS
    if unknown_imports:
        errors.append("core gained non-standard imports: %s" % ", ".join(sorted(unknown_imports)))
    if imports & VENDOR_IMPORTS:
        errors.append("core must not import vendor SDKs")
    # urllib.parse is used only for deterministic URL parsing.  Network-capable
    # urllib.request remains forbidden.
    for path in (ROOT / "mcp" / "jstack").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "urllib.request" in text or "http.client" in text or "socket." in text:
            errors.append("core must not add a network-enabled evidence importer: %s" % path.relative_to(ROOT))

    sync = _load_module("jstack_boundary_sync", ROOT / "scripts" / "sync_artifacts.py")
    managed_paths = [*sync.FILE_MAP.keys(), *(target for targets in sync.FILE_MAP.values() for target in targets)]
    if any("evals" in path.parts for path in managed_paths):
        errors.append("Proof Plane files must not be synchronized into installed artifacts")
    if any("evals" in source.parts or "evals" in target.parts for source, target in sync.TREE_MIRRORS):
        errors.append("Proof Plane trees must not be mirrored into installed artifacts")
    if any("evals" in path.parts for path in (ROOT / "plugin").rglob("*")):
        errors.append("umbrella plugin must not package the Proof Plane")
    if any("evals" in path.parts for path in (ROOT / "plugins").rglob("*")):
        errors.append("dedicated plugins must not package the Proof Plane")
    if "evals" in imports:
        errors.append("installed MCP must not import the Proof Plane")
    if not PROOF_MAINTAINER_ROOT.is_dir():
        errors.append("maintainer-only Proof Plane tooling is missing")
    else:
        proof_imports = _absolute_import_roots(PROOF_MAINTAINER_ROOT)
        if proof_imports & VENDOR_IMPORTS:
            errors.append("maintainer Proof Plane must not import vendor SDKs")
        if any("tools/proof_plane" in path.as_posix() for path in managed_paths):
            errors.append("maintainer Proof Plane tools must not be synchronized into installed artifacts")
        for install_root in (ROOT / "plugin", ROOT / "plugins", ROOT / "mcp"):
            if any("proof_plane" in path.parts for path in install_root.rglob("*")):
                errors.append("installed artifacts must not package maintainer Proof Plane tools")
        for path in (ROOT / "mcp" / "jstack").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "tools.proof_plane" in text:
                errors.append("installed MCP must not import maintainer Proof Plane tools")
    errors.extend(_evals_forbidden_actions())
    return errors


def main() -> int:
    errors = check_boundaries()
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print(
        "JStack product boundaries are intact: six commands, 58 canonical tools, "
        "52 frozen aliases, stdlib core, no packaged Proof Plane authority."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
