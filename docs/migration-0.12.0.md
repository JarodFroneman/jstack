# Migrating to JStack 0.12.0

JStack `0.12.0` adds Graphify-backed Project Intelligence to the stable
Unified Engineering OS. It extends the existing command workflows and receipt
plane without adding a slash command, standalone skill, second router, or core
runtime dependency.

The word **stable** identifies the release channel and compatibility target.
It does not claim that a generated graph is complete or semantically correct,
that every language is supported, or that graph evidence can replace direct
source inspection, tests, scanners, review, or human judgment.

## Compatibility preserved

- The six public commands remain unchanged:
  `/j-stack-dev`, `/jstack-subagents`, `/jstack-full-team`, `/jstack-loop`,
  `/jstack-audit`, and `/jstack-evidence-builder`.
- The 52 frozen legacy `gstack_*` aliases remain unchanged. Project
  Intelligence has no compatibility aliases.
- The JStack runtime core remains Python-standard-library only.
- Existing Prompt Compiler, Product Interface, Audit, Loop, Program, Launch
  Assurance, security, QA, and release authority boundaries remain intact.
- Existing products still preserve and extend their documented architecture;
  the graph is context and evidence, not redesign authority.

## What changes

- Five canonical MCP operations increase the canonical surface from 60 to 65:
  `jstack_graph_index`, `jstack_graph_query`, `jstack_graph_impact`,
  `jstack_graph_refresh`, and `jstack_graph_finalize`.
- Material cross-module, architecture, security, database, dependency, audit,
  team, loop, program, and release work now requires exact-state Project
  Intelligence evidence. Trivial, non-code, empty, greenfield, and unsupported
  cases return an explicit skip or deferral disclosure.
- Strong relationship evidence is limited to source-anchored `EXTRACTED`
  edges. Inferred, ambiguous, and unanchored extracted relationships remain
  advisory and must be verified in source before use.
- Material work produces a private native `graph.html` visualization under
  `~/.jstack/project-intelligence/<repo-id>/`.
- The optional local AST provider is pinned to `graphifyy==0.9.52`, source
  commit `680e3ed8edd3dc1fa1961050912941880b778207`, and a verified top-level wheel
  digest. It is installed transactionally in an isolated managed runtime under
  `~/.jstack/tools/graphify/`.

Hosted Graphify services, semantic APIs, listeners, HTTP MCP, Git hooks,
repository instruction edits, and Graphify skills are not installed.

## Before upgrading

1. Record the active JStack version, plugin layout, MCP path, marketplace
   source, configuration hash, tool inventory, and `~/.jstack` inventory.
2. Preserve the complete `v0.11.0` installation as one rollback unit,
   including plugin source/cache, shared MCP, marketplace metadata, and Codex
   configuration.
3. Preserve all existing JStack state. Do not remove loops, programs, UI
   evidence, mastery state, or keys.
4. Verify that the checkout is the exact annotated `v0.12.0` tag and resolves
   to the published stable GitHub Release commit.
5. Decide whether to enable the optional managed Graphify provider. Without
   it, material applicable workflows fail closed with provider-unavailable
   evidence instead of silently using another implementation.

## Validate the source

From the immutable `v0.12.0` checkout, run:

```bash
python3 scripts/sync_artifacts.py --check
python3 scripts/check_contract_compatibility.py
python3 scripts/check_product_boundaries.py
python3 -m evals.runner.cli verify-lock
python3 -m compileall -q mcp scripts tests evals
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

The release pull request must also pass the complete cross-platform CI matrix
and target-bound CodeQL. JStack's bounded heuristic secret scan does not
replace independent release scanning.

## Install and verify

Use exactly one distribution layout from
[installation.md](installation.md). To enable the pinned local provider with a
transactional direct install, use:

```bash
python3 scripts/install.py --with-project-intelligence
```

Restart Codex or open a fresh task after activation. Verify:

- all six dedicated plugins report `0.12.0` and are enabled;
- the shared MCP initialize response reports `0.12.0`;
- `tools/list` reports 65 canonical tools and 52 frozen aliases;
- the five canonical Project Intelligence operations are present exactly once;
- exactly one `product-ui-design` skill remains active through `j-stack-dev`;
- the managed provider reports `graphifyy==0.9.52` and the pinned catalog
  digest when enabled;
- installed plugin, MCP, and provider bytes match the release candidate; and
- the installed MCP smoke test and one isolated repository index/query/impact/
  refresh/finalize cycle pass.

## State and receipts

The upgrade does not migrate or delete existing loop, program, UI, audit,
mastery, or context state. Project Intelligence creates a separate private
per-repository namespace. Receipts bound to a replaced JStack version, policy,
provider catalog, Git state, graph snapshot, or changed-path set must be
reissued.

## Rollback

If activation, startup, inventory, hash, provider, or smoke verification fails:

1. stop using the `0.12.0` candidate;
2. restore the complete preserved `v0.11.0` plugin, cache, MCP, marketplace,
   and configuration unit;
3. remove no Project Intelligence state unless corruption is demonstrated;
4. restart Codex; and
5. verify the restored `0.11.0` version, 60/52 tool surface, hashes, and MCP
   smoke test.

Do not create a mixed installation by restoring individual generated files.

## Further reading

- [Graphify-backed Project Intelligence](project-intelligence.md)
- [ADR 0046](adr/0046-graphify-project-intelligence.md)
- [Installation and provider boundary](installation.md)
- [Security policy](../SECURITY.md)
- [Complete changelog](../CHANGELOG.md)
