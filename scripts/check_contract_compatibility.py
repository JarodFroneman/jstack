#!/usr/bin/env python3
"""Fail when alpha.9 public contracts drift without a versioned successor."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "contracts" / "v0.10.0-alpha.9.json"


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _raw_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_server() -> Any:
    server_path = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
    sys.path.insert(0, str(server_path.parent))
    spec = importlib.util.spec_from_file_location("jstack_contract_check_server", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the JStack MCP server")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_contracts(fixture_path: Path = DEFAULT_FIXTURE) -> list[str]:
    fixture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    required = {
        "schemaVersion",
        "release",
        "baselineCommit",
        "commandNames",
        "pluginLayouts",
        "canonicalToolInputSchemaSha256",
        "legacyAliases",
        "coreSchemaFilesSha256",
        "persistedSchemaMarkers",
        "protocolVersions",
        "productInvariants",
    }
    if not isinstance(fixture, dict) or set(fixture) != required:
        return ["contract fixture does not have the closed v1 field set"]
    if fixture["schemaVersion"] != "jstack.contract-snapshot.v1":
        return ["contract fixture schemaVersion is unsupported"]

    errors: list[str] = []
    server = _load_server()
    command_names = sorted(path.name for path in (ROOT / "prompts").glob("*.md"))
    if command_names != fixture["commandNames"]:
        errors.append("five-command contract drift: %s" % command_names)
    plugin_layouts = sorted(
        ["plugin/.codex-plugin/plugin.json"]
        + [path.relative_to(ROOT).as_posix() for path in ROOT.glob("plugins/*/.codex-plugin/plugin.json")]
    )
    if plugin_layouts != fixture["pluginLayouts"]:
        errors.append("plugin-layout contract drift")

    canonical = {
        name: _canonical_digest(meta["inputSchema"])
        for name, meta in server.TOOLS.items()
        if name.startswith("jstack_")
    }
    expected_tools: Dict[str, str] = fixture["canonicalToolInputSchemaSha256"]
    if set(canonical) != set(expected_tools):
        errors.append("canonical MCP tool names changed")
    for name in sorted(set(canonical) & set(expected_tools)):
        if canonical[name] != expected_tools[name]:
            errors.append("MCP input contract changed without a versioned successor: %s" % name)

    aliases = sorted(name for name in server.TOOLS if name.startswith("gstack_"))
    if aliases != fixture["legacyAliases"]:
        errors.append("legacy alias contract drift")

    expected_schemas: Dict[str, str] = fixture["coreSchemaFilesSha256"]
    current_schema_names = sorted(path.name for path in (ROOT / "mcp" / "jstack" / "schemas").glob("*.json"))
    if current_schema_names != sorted(expected_schemas):
        errors.append("published core schema inventory changed")
    for name in sorted(set(current_schema_names) & set(expected_schemas)):
        path = ROOT / "mcp" / "jstack" / "schemas" / name
        if _raw_digest(path) != expected_schemas[name]:
            errors.append("published v1 schema changed in place: %s" % name)

    for relative, markers in fixture["persistedSchemaMarkers"].items():
        path = ROOT / relative
        if not path.is_file():
            errors.append("persisted-state contract file is missing: %s" % relative)
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                errors.append("persisted-state schema marker changed: %s -> %s" % (relative, marker))

    if sorted(server.SUPPORTED_PROTOCOL_VERSIONS) != fixture["protocolVersions"]:
        errors.append("MCP protocol compatibility set changed")
    invariants = fixture["productInvariants"]
    if len(canonical) != invariants["canonicalToolCount"]:
        errors.append("canonical tool count changed")
    if len(aliases) != invariants["legacyAliasCount"]:
        errors.append("legacy alias count changed")
    if len(command_names) != invariants["commandCount"]:
        errors.append("command count changed")
    if server.SERVER_NAME != invariants["serverName"]:
        errors.append("MCP server name changed")
    if len(server.capability_core.ROSTER_ROLE_IDS) != invariants["roleCount"]:
        errors.append("core role count changed")
    if len(server.capability_core.load_catalog()["capabilities"]) != invariants["capabilityCount"]:
        errors.append("capability count changed")
    launch_catalog = server.launch_core.load_catalog()
    if len(launch_catalog["controls"]) != invariants["launchControlCount"]:
        errors.append("launch control count changed")
    if len(launch_catalog["surfaces"]) != invariants["launchSurfaceCount"]:
        errors.append("launch surface count changed")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()
    errors = check_contracts(args.fixture)
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print("JStack alpha.9 public contracts remain compatible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
