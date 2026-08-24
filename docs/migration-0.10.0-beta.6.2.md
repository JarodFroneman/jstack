# Migrating to JStack 0.10.0-beta.6.2

Beta.6.2 is a compatibility-preserving Product Interface detector hardening
release on top of Beta.6.1. It adds no slash command, MCP tool, model-provider
call, runtime dependency, persisted-state migration, or action authority.

## What changes

- Readable ambiguous candidates that exceed the normal 256 KB UI read limit
  receive a descriptor-safe, stable-identity scan capped at 1 MB.
- When an ambiguous file is larger than that cap, detection records
  `inspectionTruncated: true` and returns `review-required` instead of throwing.
- Whole-repository detection stops after the first content-truncated candidate
  because its result is already incomplete; later files remain unclassified
  rather than being represented as inspected.
- Changed-scope applicability also returns `review-required` for incomplete
  content inspection. Candidate-time Product Interface finalization remains
  fail-closed until all changed UI-capable files can be inspected completely.
- Unsafe, unreadable, non-regular, identity-unstable, and oversized strong UI
  files remain fail-closed when directly inspected.
- All six commands, 59 canonical tools, 52 frozen aliases, Prompt Compiler
  behavior, Product UI motion contracts, and existing public schema versions
  remain compatible.

## Upgrade

1. Retain the complete Beta.6.1 MCP, source, cache, marketplace,
   configuration, and plugin inventory as one rollback unit.
2. Install from the exact annotated `v0.10.0-beta.6.2` GitHub prerelease tag.
3. Keep all six dedicated plugins and the MCP on the same Beta.6.2 version.
4. Keep the umbrella plugin absent and Beta.6.1 installed but disabled.
5. Restart Codex or open a fresh task.
6. Verify MCP version `0.10.0-beta.6.2`, 59 canonical tools, 52 frozen aliases,
   six enabled plugins, exact source/cache parity, and JSONL smoke behavior.
7. In a repository containing a readable Python `app/server.py` larger than
   1 MB, verify `jstack_detect_project` returns `review-required` with
   `inspectionTruncated: true` and `contentReturned: false` instead of throwing.
8. Verify a directly scoped unsafe or oversized strong UI file still fails
   closed.

Use isolated side-by-side MCP, marketplace, and cache namespaces. Do not
replace an in-use Beta.6.1 runtime path.

## Receipt invalidation

Prompt compilation, context, planning, loop, program, UI, and release receipts
remain server-version-bound. Recreate them after upgrading. No persisted loop,
program, mastery, or private UI evidence migration is required.

## Rollback

Restore the complete Beta.6.1 deployment unit and restart Codex. Do not mix
MCP, plugin source, cache, marketplace, or configuration versions. Preserve
`~/.jstack` state; Beta.6.2 adds no state migration.

This remains an unvalidated prerelease. It claims deterministic implementation,
compatibility, and test evidence, not production readiness, complete UI
classification after a truncated scan, or completion of the deferred Beta.1
Proof Study.
