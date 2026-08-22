# Migrating To JStack v0.10.0-beta.4

## Release Boundary

`v0.10.0-beta.4` adds the deterministic two-stage Prompt Compiler. It extends
the Adaptive Context Gate; it does not add a command, model provider, hidden
reasoning store, or execution authority.

This is a prerelease. It claims schema, receipt, compatibility, and test
coverage, not measured prompt-quality uplift or completion of the deferred
Beta.1 Proof Study.

## Public Changes

- Canonical tools increase from 56 to 57 with `jstack_prompt_compile`.
- All six command names and dedicated plugins remain unchanged.
- All 52 `gstack_*` aliases remain frozen; no compiler alias is added.
- New closed schemas: `jstack.prompt-intent.v1` and
  `jstack.prompt-compilation.v1`.
- Existing context, Loop, and Program callers use an automatic deterministic
  compatibility bridge. Official workflows use explicit Stage A and Stage B.
- Loop and Program readiness receipts bind the compilation digest.

## Upgrade

1. Retain the complete Beta.3 MCP, source, cache, marketplace, configuration,
   and plugin inventory as the rollback unit.
2. Install from the exact annotated `v0.10.0-beta.4` prerelease tag.
3. Keep all six dedicated plugins and the MCP on the same Beta.4 version.
4. Restart Codex or open a fresh task.
5. Verify MCP version `0.10.0-beta.4`, 57 canonical tools, 52 aliases, six
   enabled plugins, and exact source/cache parity.
6. Verify `jstack_prompt_compile(stage="intent")` returns no project binding
   and that Stage B binds the current Git state before planning.

Use a versioned side-by-side MCP and cache namespace when active processes
cannot be drained. Do not replace an in-use physical Beta.3 runtime path.

## Rollback

Set `JSTACK_PROMPT_COMPILER_MODE=disabled` and restart the MCP for an immediate
behavioral rollback, or restore the complete Beta.3 deployment unit. Do not mix
MCP, plugin source, cache, and marketplace versions. Preserve `~/.jstack`
state; Beta.4 adds no state migration.
