# ADR 0035: gstack Inputs Require Immutable Provenance And Deliberate Sync

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: JStack's existing `THIRD_PARTY_NOTICES.md` architecture

## Context

Upstream `main`, generated host skills, and automatic update behavior are
mutable. Without source digests and adaptation records, reviewers cannot tell
what was researched, copied, re-expressed, wrapped, or changed locally.

## Decision

Every material gstack-derived item records repository, immutable commit,
upstream version, source files, license, adaptation class, local target, local
modifications, source digest, and synchronization status. Allowed adaptation
classes are `RESEARCHED`, `ADAPTED`, `WRAPPED`, `VENDORED`, and `FORKED`, with
JStack-native material explicitly separate.

Prefer original JStack adaptations and thin wrappers. Vendoring or forking
requires a specific decision and license/security review. Upstream is never
loaded from mutable `main` at runtime. Sync is a maintainer workflow: resolve,
diff, impact analysis, license check, security review, compatibility test,
adapt, and regress. There is no silent enterprise auto-update path.

Provenance extends current third-party notices rather than creating a second
license ledger. Generated plugin copies point back to canonical JStack sources.

## Rejected Alternatives

- Track only a repository URL: rejected because content is mutable.
- Run upstream self-update: rejected because it can silently change policy.
- Copy prompts without file-level attribution: rejected as unauditable.

## Consequences

Updates require deliberate maintenance but become reviewable and reproducible.
Stage 4 implements the immutable manifest and its validators.
