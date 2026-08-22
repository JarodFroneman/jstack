#!/usr/bin/env python3
"""Preserve alpha.9 contracts while allowing closed Product UI successors."""

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
ADDITIVE_CANONICAL_TOOLS = frozenset(
    {
        "jstack_ui_contract",
        "jstack_ui_finalize",
        "jstack_ui_reference_contract",
        "jstack_ui_reference_finalize",
        "jstack_ui_motion_spec",
        "jstack_prompt_compile",
    }
)
ADDITIVE_COMMAND_NAMES = frozenset({"jstack-evidence-builder.md"})
ADDITIVE_PLUGIN_LAYOUTS = frozenset(
    {"plugins/jstack-evidence-builder/.codex-plugin/plugin.json"}
)
ADDITIVE_EXISTING_TOOL_FIELDS = {
    **{
        name: {
            "capability_selection_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
                "description": (
                    "Optional exact selectionDigest from jstack_plan, "
                    "jstack_team_plan, or a loop capability contract. Required "
                    "to disambiguate Product Interface routing when ordinary "
                    "and UI plans use the same role roster."
                ),
            }
        }
        for name in (
            "jstack_specialist_result",
            "jstack_specialist_handoff_check",
        )
    },
    "jstack_loop_goal_readiness": {
        "ui_contract_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": (
                "Optional clean-baseline receipt from jstack_ui_contract. Supplying "
                "it creates an explicit loop contract v2 and requires a ui "
                "acceptance criterion."
            ),
        }
    },
    "jstack_loop_start": {
        "ui_contract_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": (
                "The same Product Interface baseline receipt bound into goal "
                "readiness for a UI loop."
            ),
        }
    },
    "jstack_loop_checkpoint": {
        "ui_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": (
                "A current candidate-bound receipt from jstack_ui_finalize. It "
                "satisfies only a dedicated ui criterion and never substitutes for "
                "QA, audit, security, launch, or human evidence."
            ),
        }
    },
    "jstack_loop_finalize": {
        "ui_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": (
                "A current candidate-bound receipt from jstack_ui_finalize. It "
                "satisfies only a dedicated ui criterion and never substitutes for "
                "QA, audit, security, launch, or human evidence."
            ),
        }
    },
    "jstack_program_finalize": {
        "ui_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": (
                "A current candidate-bound receipt from jstack_ui_finalize. It "
                "satisfies only a dedicated ui criterion and never substitutes for "
                "QA, audit, security, launch, or human evidence."
            ),
        }
    },
    **{
        name: {
            "ui_contract_receipt": {
                "type": "string",
                "maxLength": 250_000,
                "description": (
                    "Opaque receipt returned by jstack_ui_contract for this exact "
                    "program baseline and policy state."
                ),
            }
        }
        for name in (
            "jstack_program_goal_readiness",
            "jstack_program_start",
            "jstack_program_revise",
        )
    },
    "jstack_release_readiness": {
        "ui_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": (
                "Current jstack_ui_finalize receipt; required automatically when "
                "repository evidence shows UI changes in the release delta."
            ),
        }
    }
}
PROMPT_COMPILATION_INPUT_FIELDS = {
    "prompt_compilation_receipt": {
        "type": "string",
        "maxLength": 250_000,
        "description": (
            "Optional exact approval-bound Stage B receipt from jstack_prompt_compile. Supply it with prompt_contract to prove explicit pre-inspection compilation and exact final-prompt approval; legacy callers use the deterministic compatibility bridge."
        ),
    },
    "prompt_contract": {
        "type": "object",
        "description": (
            "Exact approved jstack.prompt-compilation.v2 object returned with prompt_compilation_receipt."
        ),
    },
}
for _prompt_bound_tool in (
    "jstack_loop_goal_readiness",
    "jstack_program_goal_readiness",
):
    ADDITIVE_EXISTING_TOOL_FIELDS.setdefault(_prompt_bound_tool, {}).update(
        PROMPT_COMPILATION_INPUT_FIELDS
    )
LOOP_ACCEPTANCE_VERIFIER_ENUM_PATH = (
    "properties",
    "acceptance_criteria",
    "items",
    "properties",
    "verifier",
    "properties",
    "type",
    "enum",
)
PROGRAM_PHASE_VERIFIER_ENUM_PATH = (
    "properties",
    "phases",
    "items",
    "properties",
    "acceptance_criteria",
    "items",
    "properties",
    "verifier",
    "properties",
    "type",
    "enum",
)
PROGRAM_FINAL_VERIFIER_ENUM_PATH = (
    "properties",
    "final_acceptance_criteria",
    "items",
    "properties",
    "verifier",
    "properties",
    "type",
    "enum",
)
FROZEN_LOOP_VERIFIER_TYPES = (
    "qa",
    "security",
    "audit",
    "launch",
    "review",
    "artifact",
    "human",
)
FROZEN_PROGRAM_VERIFIER_TYPES = (
    "qa",
    "security",
    "audit",
    "launch",
    "review",
    "artifact",
)
ADDITIVE_EXISTING_TOOL_ENUMS = {
    name: {LOOP_ACCEPTANCE_VERIFIER_ENUM_PATH: FROZEN_LOOP_VERIFIER_TYPES + ("ui",)}
    for name in (
        "jstack_loop_goal_readiness",
        "jstack_loop_start",
        "jstack_loop_revise",
    )
}
ADDITIVE_EXISTING_TOOL_ENUMS.update(
    {
        name: {
            PROGRAM_PHASE_VERIFIER_ENUM_PATH: FROZEN_PROGRAM_VERIFIER_TYPES + ("ui",),
            PROGRAM_FINAL_VERIFIER_ENUM_PATH: FROZEN_PROGRAM_VERIFIER_TYPES + ("ui",),
        }
        for name in (
            "jstack_program_goal_readiness",
            "jstack_program_start",
            "jstack_program_revise",
        )
    }
)
ADDITIVE_SCHEMA_FILES = frozenset(
    {
        "ui-catalog.v1.schema.json",
        "ui-contract.v1.schema.json",
        "ui-contract.v2.schema.json",
        "ui-evidence.v1.schema.json",
        "ui-finalization.v1.schema.json",
        "ui-motion-spec.v1.schema.json",
        "ui-objective-result.v1.schema.json",
        "ui-product-observation.v1.schema.json",
        "ui-reference-analysis.v1.schema.json",
        "ui-reference-bundle.v1.schema.json",
        "ui-reference-contract.v1.schema.json",
        "prompt-intent.v1.schema.json",
        "prompt-compilation.v1.schema.json",
        "prompt-compilation.v2.schema.json",
    }
)
FROZEN_CANONICAL_TOOL_COUNT = 52
FROZEN_ALIAS_COUNT = 52
LIVE_CANONICAL_TOOL_COUNT = 58


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _portable_text_digest(path: Path) -> str:
    """Hash published text contracts independently of checkout line endings."""
    normalized = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def _matches_approved_existing_tool_successor(
    name: str,
    schema: Any,
    frozen_digest: str,
) -> bool:
    approved_fields = ADDITIVE_EXISTING_TOOL_FIELDS.get(name, {})
    approved_enums = ADDITIVE_EXISTING_TOOL_ENUMS.get(name, {})
    if not isinstance(schema, dict) or not (approved_fields or approved_enums):
        return False
    properties = schema.get("properties")
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        return False
    if any(field in required for field in approved_fields):
        return False
    if any(properties.get(field) != contract for field, contract in approved_fields.items()):
        return False
    frozen_shape = json.loads(json.dumps(schema, ensure_ascii=False))
    for field in approved_fields:
        del frozen_shape["properties"][field]
    for path, expected in approved_enums.items():
        current: Any = frozen_shape
        try:
            for component in path[:-1]:
                current = current[component]
            actual = current[path[-1]]
        except (KeyError, TypeError):
            return False
        if actual != list(expected):
            return False
        current[path[-1]] = list(expected[:-1])
    return _canonical_digest(frozen_shape) == frozen_digest


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
    expected_commands = set(fixture["commandNames"]) | ADDITIVE_COMMAND_NAMES
    if set(command_names) != expected_commands:
        errors.append("command contract changed outside the approved additive surface: %s" % command_names)
    plugin_layouts = sorted(
        ["plugin/.codex-plugin/plugin.json"]
        + [path.relative_to(ROOT).as_posix() for path in ROOT.glob("plugins/*/.codex-plugin/plugin.json")]
    )
    expected_plugin_layouts = set(fixture["pluginLayouts"]) | ADDITIVE_PLUGIN_LAYOUTS
    if set(plugin_layouts) != expected_plugin_layouts:
        errors.append("plugin layout changed outside the approved additive surface")

    canonical = {
        name: _canonical_digest(meta["inputSchema"])
        for name, meta in server.TOOLS.items()
        if name.startswith("jstack_")
    }
    expected_tools: Dict[str, str] = fixture["canonicalToolInputSchemaSha256"]
    expected_live_tools = set(expected_tools) | ADDITIVE_CANONICAL_TOOLS
    if set(canonical) != expected_live_tools:
        errors.append("canonical MCP tool names changed outside the approved additive contract")
    for name in sorted(set(canonical) & set(expected_tools)):
        if canonical[name] == expected_tools[name]:
            if name in ADDITIVE_EXISTING_TOOL_FIELDS or name in ADDITIVE_EXISTING_TOOL_ENUMS:
                errors.append(
                    "approved additive MCP input successor delta is missing: %s"
                    % name
                )
        elif not _matches_approved_existing_tool_successor(
            name,
            server.TOOLS[name]["inputSchema"],
            expected_tools[name],
        ):
            errors.append("MCP input contract changed without a versioned successor: %s" % name)

    aliases = sorted(name for name in server.TOOLS if name.startswith("gstack_"))
    if aliases != fixture["legacyAliases"]:
        errors.append("legacy alias contract drift")

    expected_schemas: Dict[str, str] = fixture["coreSchemaFilesSha256"]
    current_schema_names = sorted(path.name for path in (ROOT / "mcp" / "jstack" / "schemas").glob("*.json"))
    expected_live_schemas = set(expected_schemas) | ADDITIVE_SCHEMA_FILES
    if set(current_schema_names) != expected_live_schemas:
        errors.append("published core schema inventory changed outside the approved additive contract")
    for name in sorted(set(current_schema_names) & set(expected_schemas)):
        path = ROOT / "mcp" / "jstack" / "schemas" / name
        if _portable_text_digest(path) != expected_schemas[name]:
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
    if (
        len(expected_tools) != FROZEN_CANONICAL_TOOL_COUNT
        or invariants["canonicalToolCount"] != FROZEN_CANONICAL_TOOL_COUNT
    ):
        errors.append("frozen canonical tool snapshot is internally inconsistent")
    if len(canonical) != LIVE_CANONICAL_TOOL_COUNT:
        errors.append("canonical tool count changed outside the approved additive contract")
    if (
        len(aliases) != FROZEN_ALIAS_COUNT
        or invariants["legacyAliasCount"] != FROZEN_ALIAS_COUNT
    ):
        errors.append("legacy alias count changed")
    if len(command_names) != invariants["commandCount"] + len(ADDITIVE_COMMAND_NAMES):
        errors.append("command count changed outside the approved additive surface")
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
