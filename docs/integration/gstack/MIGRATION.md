# Unified Engineering OS Migration and Rollback

## Current boundary

This document describes additive adoption of the Unified Engineering OS
packaged for stable `v0.11.0`. Stage 20 itself changed documentation,
provenance bindings, and documentation tests only; the separately authorized
release packaging advances version and distribution metadata without changing
the public command, tool, or alias inventory.

Publication and global installation remain separate actions requiring explicit
authority and fresh release evidence. A version-bearing source file or receipt
does not prove that either action occurred.

## Compatibility contract

The target architecture preserves:

- the six public JStack commands;
- 60 canonical `jstack_*` MCP tools;
- 52 frozen legacy `gstack_*` aliases;
- the Python-standard-library core;
- existing Prompt Compilation, Context Readiness, canonical roles, Loop,
  Program, Audit, Launch Assurance, and Product Interface authorities;
- deterministic legacy behavior for omitted additive fields; and
- upstream gstack as optional research/provider input rather than a required
  runtime.

New contract versions and optional fields are additive. Frozen aliases do not
receive new canonical-only Product Interface or provider tools. An old caller
must not be silently reinterpreted as approving a profile, provider, broad
scope, external action, release, or deployment.

## Adoption modes

The Prompt Compiler already supports `disabled`, `shadow`, `preview`, and
`enforced` through its documented compiler mode. The broader Unified OS should
use the same rollout vocabulary where a feature needs staged adoption; this is
not a claim that every candidate module exposes an independent feature flag.

| Mode | Required behavior |
| --- | --- |
| Disabled | Preserve the prior released path; do not emit or require the new contract |
| Shadow | Compute bounded results for comparison without changing routing or authority |
| Preview | Expose the result and require explicit selection/approval where material |
| Enforced | Require the validated contract and fail closed according to active policy |

Moving between modes must be explicit, observable, reversible, and included in
the relevant receipt/policy binding. Shadow or preview evidence cannot be
relabelled as enforced evidence.

## Migration sequence

1. **Inventory:** record the installed JStack version, host, project mode,
   active policies, optional providers, receipts, and generated plugin unit.
2. **Validate candidate:** run focused stage tests plus compatibility,
   Product Boundary, sync, provenance, compilation, and proportionate full
   verification.
3. **Preview contracts:** inspect Team Composer, profile, methodology, provider,
   host, delivery, security, and release projections without expanding action
   authority.
4. **Exercise representative projects:** include Git, non-Git/artifact-only,
   UI, backend, security-sensitive, provider-unavailable, and legacy direct
   callers.
5. **Prepare rollback:** preserve the complete prior plugin unit and invalidate
   receipts on version/catalog/policy/provider/host/candidate drift.
6. **Release separately:** update version and release metadata only after an
   explicit release request and fresh candidate-bound readiness evidence.
7. **Install transactionally:** stage and validate the complete plugin before
   replacement; retain the prior complete unit for rollback.

## Canonical and generated artifacts

Canonical source lives in the root `mcp/`, `prompts/`, `skills/`, schemas,
catalogs, and documentation paths. `scripts/sync_artifacts.py` owns the
generated umbrella `plugin/` and dedicated `plugins/` copies. Generated files
must never be edited as an independent source of truth.

An integration change is incomplete when the generator map, inventory, bytes,
versions, or provenance targets are stale. Installation must replace a
coherent generated plugin unit rather than mixing files from different
versions.

## Receipt invalidation

Recompile or reissue affected contracts when any material binding changes,
including:

- user goal, requested task mode, accepted assumption, or explicit authority;
- project, repository HEAD/fingerprint, candidate, or workflow;
- risk, profile, scope strategy, host, provider, policy, or catalog;
- Prompt Compiler/template, schema, Team Composer, or plugin version; or
- material external evidence or upstream provenance.

Readiness and evidence remain non-authorizing after reissue. Existing receipts
cannot approve a new Git, release, deployment, production, or external action.

## Optional runtimes and hosts

Missing optional gstack, browser, scanner, Node, Bun, vendor, or host features
must report `UNAVAILABLE` or `UNSUPPORTED` without breaking unrelated JStack
workflows or fabricating parity. Codex is the release-tested full host for the
candidate, Claude Code is preview, and generic MCP is protocol-only. MCP
connectivity alone does not prove command, skill, subagent, continuation,
approval, or provider equivalence.

The browser project-script runner is not an operating-system or network
sandbox. Do not enable it for untrusted repositories without separately
provisioned isolation.

## Git and non-Git projects

Git-backed projects can bind receipts to repository and candidate identity and
can use Git-dependent evidence tools. Non-Git or artifact-only projects retain
read-only discovery and planning where supported, while Git evidence, release
readiness, and Git mutation tools remain unavailable. Migration must not invent
a Git identity or lower a required evidence floor for those projects.

## Rollback

Rollback is a complete-unit operation:

1. stop new work that depends on the candidate contracts;
2. restore the previously validated plugin unit and configuration;
3. invalidate receipts bound to the replaced version, policy, catalog,
   provider, host, schema, or candidate;
4. rerun runtime, compatibility, and smoke checks; and
5. record which candidate evidence no longer applies.

Do not roll back by copying individual generated files or by retaining a new
manifest with old canonical sources.

## Claims and release readiness

Stage 19 is `NOT_MEASURED`: its 168-cell protocol has not produced comparative
results. Migration or release notes must not claim that the combined candidate
outperforms baseline JStack, gstack, or a base agent without a separately run,
reproducible, independently reviewed study.

Stable publication does not change the empirical boundary or make receipts
authorizing. Commit, publication, release, deployment, global installation,
and production mutation remain distinct actions governed by explicit user
scope and normal host/provider controls.

## Related documents

- [README.md](README.md)
- [PROFILE_MODEL.md](PROFILE_MODEL.md)
- [PROVIDER_MODEL.md](PROVIDER_MODEL.md)
- [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md)
- [EVALUATION_PLAN.md](EVALUATION_PLAN.md)
