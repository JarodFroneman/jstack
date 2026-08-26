# ADR 0044: Unified OS Adoption Is Additive, Feature-Flagged, And Reversible

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0020](0020-proof-foundation.md)

## Context

JStack has six public commands, 59 canonical tools, 52 frozen aliases,
versioned schemas, installed plugin copies, persisted Loop and Program state,
and users on legacy direct MCP paths. Dynamic teams and providers cannot be
introduced by silently rewriting those contracts.

## Decision

Evolve canonical sources additively and propagate generated copies only through
`scripts/sync_artifacts.py`. Preserve command names and frozen aliases. New
contracts receive new schema versions; existing receipt and state formats stay
valid unless a documented security invalidation or migration applies.

Introduce Unified OS behavior behind `disabled`, `shadow`, `preview`, and
`enforced` modes. Shadow produces non-authorizing comparison data. Preview is
explicit and reversible. Enforced becomes eligible only after compatibility,
security, performance, evaluation, installer, and rollback gates pass.

Legacy MCP calls use a deterministic compatibility bridge or return a precise
migration requirement; they never fabricate missing approvals. Non-Git and
artifact-only projects receive explicit unsupported/unavailable semantics where
candidate binding cannot be satisfied.

Rollback restores the prior complete plugin unit and invalidates receipts tied
to changed policy, schema, catalog, provider, or candidate fingerprints. It
does not delete user project data.

## Rejected Alternatives

- Big-bang replacement: rejected for contract and state risk.
- Maintain hand-edited plugin copies: rejected because canonical drift is
  already guarded.
- Silent behavior change under existing receipts: rejected as unsafe.

## Consequences

Migration takes longer and requires dual-path testing, but existing users gain
a reviewable opt-in path and a reliable rollback boundary.
