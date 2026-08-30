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
        "jstack_ui_motion_finalize",
        "jstack_prompt_compile",
        "jstack_browser_capture",
        "jstack_graph_index",
        "jstack_graph_query",
        "jstack_graph_impact",
        "jstack_graph_refresh",
        "jstack_graph_finalize",
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
    },
    "jstack_ui_finalize": {
        "motion_spec_receipt": {
            "type": "string",
            "minLength": 1,
            "maxLength": 250_000,
            "description": (
                "For motion-applicable work, the exact Beta.5 creation-time motion specification receipt. Must be paired with motion_finalization_receipt; static work omits both."
            ),
        },
        "motion_finalization_receipt": {
            "type": "string",
            "minLength": 1,
            "maxLength": 250_000,
            "description": (
                "For motion-applicable work, the exact current-candidate receipt from jstack_ui_motion_finalize. Must be paired with motion_spec_receipt."
            ),
        },
    }
}
ADDITIVE_EXISTING_TOOL_FIELDS["jstack_specialist_result"].update(
    {
        "investigation_contract": {
            "type": "object",
            "description": "Exact jstack.investigation.v1 contract for the receipt-bound root-cause-investigator. The packaged investigation-contract.v1.schema.json and deterministic server validator are authoritative.",
        },
        "specialist_id": {
            "type": "string",
            "minLength": 2,
            "maxLength": 100,
            "description": "Logical specialistId from dynamicReceiptAssignments. Supply only with team_plan_receipt and physical_agent_id.",
        },
        "physical_agent_id": {
            "type": "string",
            "minLength": 2,
            "maxLength": 100,
            "description": "Exact physicalAgentId assigned to specialist_id by the signed Unified Team Plan.",
        },
        "team_plan_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": "Exact dispatch-eligible unifiedTeamPlanReceipt returned by jstack_team_plan. When present, logical-specialist receipt v2 validation replaces the legacy fixed-role route.",
        },
    }
)
ADDITIVE_EXISTING_TOOL_FIELDS.setdefault("jstack_dispatch_check", {}).update(
    {
        "dispatch_phase": {
            "type": "string",
            "enum": ["standard", "investigation", "remediation", "browser-remediation"],
            "default": "standard",
            "description": "Stage 9/12 phase. Fix work validates investigation before remediation; a failing browser receipt uses browser-remediation to route only the original scoped Builder and require fresh re-QA.",
        },
        "investigation_receipt": {
            "type": "string",
            "maxLength": 200000,
            "description": "Exact passing root-cause specialist receipt required for remediation dispatch against the unchanged candidate.",
        },
        "browser_evidence_receipt": {
            "type": "string",
            "maxLength": 250000,
            "description": "Exact current-candidate failing browser-evidence receipt required only with dispatch_phase=browser-remediation. It is evidence, not source-write authority.",
        },
        "browser_finding": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schemaVersion", "id", "category", "severity", "title",
                "claim", "expectedBehavior", "observedBehavior",
                "reproductionStatus", "remediationRecommendation",
                "evidenceReferences", "evidenceSha256", "scenarioDigest",
                "sourceMutationAttempted",
            ],
            "properties": {
                "schemaVersion": {"const": "jstack.browser-finding.v1"},
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"},
                "category": {"type": "string", "enum": ["accessibility", "console", "content", "interaction", "network", "performance", "responsive", "visual"]},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "title": {"type": "string", "minLength": 1, "maxLength": 200},
                "claim": {"type": "string", "minLength": 1, "maxLength": 1000},
                "expectedBehavior": {"type": "string", "minLength": 1, "maxLength": 1000},
                "observedBehavior": {"type": "string", "minLength": 1, "maxLength": 1000},
                "reproductionStatus": {"type": "string", "enum": ["reproduced", "intermittent"]},
                "remediationRecommendation": {"type": "string", "minLength": 1, "maxLength": 1000},
                "evidenceReferences": {
                    "type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": True,
                    "items": {"type": "string", "pattern": "^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"},
                },
                "evidenceSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "scenarioDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "sourceMutationAttempted": {"const": False},
            },
            "description": "Exact jstack.browser-finding.v1 QA finding bound to browser_evidence_receipt. QA may recommend remediation but cannot mutate source.",
        },
    }
)
ADDITIVE_EXISTING_TOOL_FIELDS.setdefault("jstack_plan", {}).update(
    {
        "operating_profile": {
            "type": "string",
            "enum": ["solo", "professional", "enterprise"],
            "default": "professional",
            "description": "Governance floor, independent of execution topology and legacy quality_level. A weaker profile never lowers a mandatory risk floor.",
        },
        "host_id": {
            "type": "string",
            "enum": ["codex", "claude-code", "generic-mcp"],
            "default": "codex",
            "description": "Explicit host capability contract. Missing host-native features report UNAVAILABLE rather than being emulated.",
        },
    }
)
ADDITIVE_EXISTING_TOOL_FIELDS.setdefault("jstack_team_plan", {}).update(
    {
        "operating_profile": {
            "type": "string",
            "enum": ["solo", "professional", "enterprise"],
            "default": "professional",
            "description": "Governance floor, independent of team_mode. A weaker profile never lowers a mandatory risk floor.",
        },
        "host_id": {
            "type": "string",
            "enum": ["codex", "claude-code", "generic-mcp"],
            "default": "codex",
            "description": "Explicit host capability contract. MCP connectivity alone does not imply command or continuation parity.",
        },
    }
)
ADDITIVE_EXISTING_TOOL_FIELDS.setdefault("jstack_release_readiness", {}).update(
    {
        "release_strategy": {
            "type": "string",
            "enum": ["direct", "canary", "blue-green"],
            "description": "Readiness UX strategy only. It never authorizes or executes a release.",
        },
        "graph_finalization_receipt": {
            "type": "string",
            "maxLength": 100000,
            "description": "Current jstack_graph_finalize receipt; required automatically for a material release delta and bound to the exact candidate and changed-path set.",
        },
    }
)
ADDITIVE_EXISTING_TOOL_FIELDS.setdefault("jstack_audit", {}).update(
    {
        "graph_index_receipt": {
            "type": "string",
            "maxLength": 100000,
            "description": "Optional current jstack_graph_index receipt. When omitted, mandatory read-only audit project intelligence is indexed automatically.",
        }
    }
)
for _name, _description in {
    "jstack_loop_goal_readiness": "Optional current jstack_graph_index receipt; mandatory baselines are indexed automatically when omitted.",
    "jstack_loop_start": "The same project-intelligence baseline receipt used during readiness, or omit it to reuse the exact immutable current snapshot automatically.",
    "jstack_loop_revise": None,
    "jstack_program_goal_readiness": "Optional current jstack_graph_index receipt. When omitted, mandatory project intelligence is indexed automatically during readiness/start.",
    "jstack_program_start": "Optional current jstack_graph_index receipt. When omitted, mandatory project intelligence is indexed automatically during readiness/start.",
    "jstack_program_revise": "Optional current jstack_graph_index receipt. When omitted, mandatory project intelligence is indexed automatically during readiness/start.",
}.items():
    _contract = {"type": "string", "maxLength": 100000}
    if _description is not None:
        _contract["description"] = _description
    ADDITIVE_EXISTING_TOOL_FIELDS.setdefault(_name, {})[
        "graph_index_receipt"
    ] = _contract
for _name in (
    "jstack_loop_checkpoint",
    "jstack_loop_finalize",
    "jstack_program_finalize",
):
    ADDITIVE_EXISTING_TOOL_FIELDS.setdefault(_name, {}).update(
        {
            "graph_refresh_receipt": {
                "type": "string",
                "maxLength": 100000,
                "description": "Current jstack_graph_refresh receipt for a changed-code checkpoint. It must descend from the immutable graph index bound at readiness.",
            },
            "graph_finalization_receipt": {
                "type": "string",
                "maxLength": 100000,
                "description": "Current passing jstack_graph_finalize receipt for the exact completion candidate and immutable baseline graph binding.",
            },
        }
    )
ADDITIVE_EXISTING_TOOL_FIELDS["jstack_specialist_handoff_check"].update(
    {
        "team_plan_receipt": {
            "type": "string",
            "maxLength": 250_000,
            "description": "Exact dispatch-eligible unifiedTeamPlanReceipt. When present, expected_agents is the ordered role/capability projection of dynamicReceiptAssignments and handoff validates every logical specialist.",
        }
    }
)
ADDITIVE_SUCCESSOR_BASE_DIGESTS = {
    # jstack_ui_finalize was introduced after the alpha.9 frozen fixture. This
    # is its exact Beta.5 request schema before Beta.6 added the paired optional
    # motion receipt fields.
    "jstack_ui_finalize": "524fc4a68d14cf9b913400ed65c754c12f33972a85ad75684d25d60cd835d6a9",
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
        "ui-contract.v3.schema.json",
        "ui-contract.v4.schema.json",
        "ui-design-decision.v1.schema.json",
        "ui-evidence.v1.schema.json",
        "ui-finalization.v1.schema.json",
        "ui-motion-spec.v1.schema.json",
        "ui-motion-evidence.v1.schema.json",
        "ui-motion-audit.v1.schema.json",
        "ui-motion-finalization.v1.schema.json",
        "ui-motion-result.v1.schema.json",
        "ui-objective-result.v1.schema.json",
        "ui-product-observation.v1.schema.json",
        "ui-reference-analysis.v1.schema.json",
        "ui-reference-bundle.v1.schema.json",
        "ui-reference-contract.v1.schema.json",
        "prompt-intent.v1.schema.json",
        "prompt-compilation.v1.schema.json",
        "prompt-compilation.v2.schema.json",
        "unified-os-domain.v1.schema.json",
        "upstream-provenance.v1.schema.json",
        "specialist-directory.v1.schema.json",
        "team-composer-policy.v1.schema.json",
        "team-composer-request.v1.schema.json",
        "team-coordination.v2.schema.json",
        "methodology-catalog.v1.schema.json",
        "methodology-plan.v1.schema.json",
        "investigation-contract.v1.schema.json",
        "browser-provider-contract.v1.schema.json",
        "browser-provider-result.v1.schema.json",
        "browser-finding.v1.schema.json",
        "delivery-phase-evidence.v1.schema.json",
        "delivery-pipeline.v1.schema.json",
        "host-catalog.v1.schema.json",
        "host-contract.v1.schema.json",
        "release-choreography.v1.schema.json",
        "security-tooling-catalog.v1.schema.json",
        "project-intelligence-index.v1.schema.json",
        "project-intelligence-query.v1.schema.json",
        "project-intelligence-impact.v1.schema.json",
        "project-intelligence-refresh.v1.schema.json",
        "project-intelligence-finalization.v1.schema.json",
    }
)
FROZEN_CANONICAL_TOOL_COUNT = 52
FROZEN_ALIAS_COUNT = 52
LIVE_CANONICAL_TOOL_COUNT = 65


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
    for name, base_digest in sorted(ADDITIVE_SUCCESSOR_BASE_DIGESTS.items()):
        if name not in canonical:
            continue
        if canonical[name] == base_digest:
            errors.append(
                "approved additive MCP input successor delta is missing: %s" % name
            )
        elif not _matches_approved_existing_tool_successor(
            name,
            server.TOOLS[name]["inputSchema"],
            base_digest,
        ):
            errors.append(
                "MCP input contract changed outside its approved additive successor: %s"
                % name
            )

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
