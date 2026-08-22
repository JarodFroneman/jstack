# Migrating To JStack v0.10.0-beta.4.1

## Release Boundary

`v0.10.0-beta.4.1` is a compatibility-preserving Prompt Compiler amendment.
It adds an explicit human approval boundary after repository-grounded prompt
compilation and before JStack planning. It does not add a command, MCP tool,
model provider, runtime dependency, hidden-reasoning store, or execution
authority.

This remains an unvalidated prerelease. It claims deterministic schema,
approval-binding, compatibility, and test coverage, not measured prompt-quality
uplift or completion of the deferred Beta.1 Proof Study.

## Public Changes

- Canonical tools remain at 57 and all 52 `gstack_*` aliases remain frozen.
- `jstack.prompt-compilation.v2` succeeds the v1 compilation contract for
  official workflows; the v1 schema remains distributed for compatibility.
- A context-ready Stage B call returns the complete rendered prompt and an
  internal preview receipt, but no planning or context-readiness receipt.
- Official workflows display the complete prompt and wait for explicit user
  approval. A second Stage B call binds that approval to the exact prompt
  digest before issuing usable planning receipts.
- Prompt revisions invalidate prior approval. Changes to goal, task mode,
  authority, constraints, or non-goals restart Stage A; other revisions rerun
  Stage B.

## Upgrade

1. Retain the complete Beta.4 MCP, source, cache, marketplace, configuration,
   and plugin inventory as one rollback unit.
2. Install from the exact annotated `v0.10.0-beta.4.1` prerelease tag.
3. Keep all six dedicated plugins and the MCP on the same Beta.4.1 version.
4. Restart Codex or open a fresh task.
5. Verify MCP version `0.10.0-beta.4.1`, 57 canonical tools, 52 aliases, six
   enabled plugins, and exact source/cache parity.
6. Verify Stage A performs no repository read; unapproved Stage B returns the
   full prompt without planning receipts; and exact approval causes a second
   Stage B call to issue the bound readiness receipts.

Use versioned side-by-side MCP and cache namespaces when active processes
cannot be drained. Do not replace an in-use physical Beta.4 runtime path.

## Rollback

Set `JSTACK_PROMPT_COMPILER_MODE=disabled` and restart the MCP for an immediate
behavioral rollback, or restore the complete Beta.4 deployment unit. Do not
mix MCP, plugin source, cache, and marketplace versions. Preserve `~/.jstack`
state; Beta.4.1 adds no state migration.
