# ADR 0004: Program -> Phase Orchestration Protocol

- Status: Accepted
- Target release: 0.5.0
- Date: 2026-07-16

## Context

The 0.4 loop protocol safely converges one bounded goal. Large professional
projects may contain independently accepted phases, non-linear dependencies,
different execution teams, long human or external waits, and a separate final
integration boundary. Treating such work as one enormous loop loses useful
proof granularity; creating unrelated loops loses dependency and final
acceptance state.

A large multi-phase system was used as a planning example. Product logic must
not encode its domain or phase count. Different projects need different graphs.

## Decision

Add a durable Program -> Phase layer above existing bounded JStack loops.

- A program accepts a project-derived cycle-free DAG of one to the configured
  maximum phases.
- Every phase is an exact child loop contract with its own approved delivery
  mode, autonomy, risk, paths, criteria, gates, outputs, and isolation flags.
- Codex Goal mode remains the continuation engine.
- The program schedules and verifies; it does not edit, prompt itself, spawn
  agents, sign human decisions, or authorize release.
- Program finalization requires every current child proof, output, gate, and
  final criterion.

## Invariants

1. Phase count and dependency shape come from the confirmed contract, never a
   hardcoded roadmap.
2. The dependency graph rejects unknown nodes, duplicate IDs, self-edges, and
   cycles.
3. One non-terminal program owns a canonical repository's orchestration slot.
4. One bounded child loop may bind to only one phase.
5. Child goal, mode, autonomy, risk, scope, and criteria must exactly match the
   phase contract, and every program- or phase-level blocked action must be
   inherited without weakening.
6. Parallel phases require explicit safety, linked worktrees, disjoint
   top-level scopes, and remaining policy capacity.
7. Phase completion requires a current session receipt that matches validated
   durable child-loop completion state.
8. Declared outputs are rehashed at phase completion and program finalization.
9. Human gates require signed configured identities, role coverage, quorum,
   exact contract/gate binding, and freshness.
10. External gates require bounded server-hashed artifacts, provenance, and
    freshness; caller success assertions are rejected.
11. Human, external, and manual waits pause active time. Wall-clock waiting
    does not consume the active-work budget.
12. Material revisions require exact-digest readiness and invalidate changed
    phases plus all transitive dependants. All gate state is cleared because
    its attestation or evidence is bound to the prior contract digest.
13. Every mutating MCP operation is durably idempotent. A key reused for a
    different action or payload fails closed.
14. Contract history, snapshot, event chain, and pending transaction are
    mutually digest-bound and validated on every load.
15. Completion receipts never authorize any v0.7 protected external action;
    each requires its own exact signed and consumed permit under
    [ADR 0006](0006-external-action-authorization-boundary.md).

## Persistence

Program state lives outside Git under
`~/.jstack/programs/<project-hash>/<program-id>/`. The state includes current
and historical contracts, a snapshot, hash-chained JSONL events, idempotency
records, and a pending transaction journal. Files use private permissions.

Durable child attestations survive MCP restart. Session receipts intentionally
do not; finalization revalidates current evidence in the active server session.

## Identity Provider

Version 0.5 supports `signed-local`: an identity configuration maps named
approvers to roles and an environment-held HMAC key. The helper signs the exact
challenge outside Codex. This is a bounded local provider, not enterprise SSO
or cryptographic non-repudiation. Its interface is versioned for future
providers.

## Policy

Enterprise floors cap phases, parallel phases, and active minutes and require
signed approvals, current evidence, a final release audit, security evidence,
and deterministic integrated review. Repository policy may lower ceilings but
cannot weaken these floors.

## Compatibility

Existing 0.4 loop state remains readable. Pause-aware active-time fields are
derived conservatively for legacy snapshots. Programs are a new state family;
no old loop is automatically converted. Existing commands and `gstack_*`
aliases remain available.

## Rejected Alternatives

- Hardcode a fixed roadmap: domain-specific and false for other projects.
- Increase one loop's limits indefinitely: weak phase proof and recovery.
- Let a program directly execute code: duplicates delivery workflows and
  confuses authority.
- Treat approval waits as failures: misstates normal supervised operations.
- Store live program manifests in Git: creates source churn and risks merging
  mutable control-plane state.
- Trust summaries or completion booleans: assertions are not evidence.
- Permit implicit parallelism: path separation does not prove semantic safety.

## Consequences

JStack can supervise long, heterogeneous projects while preserving exact
phase evidence and human oversight. Setup is stricter: the roadmap must be
made explicit, approvals need configured identities, external evidence needs
artifacts, and final proof must be current. That friction is part of the trust
model.
