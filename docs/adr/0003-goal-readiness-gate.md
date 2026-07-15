# ADR 0003: Semantic Goal Readiness Gate

- Status: Accepted
- Date: 2026-07-15
- Target release: 0.4.1

## Context

The 0.4.0 loop protocol validates scope, autonomy, convergence, and completion
evidence, but a caller can still formulate a technically valid contract from
an underspecified prompt. Generic acceptance criteria can then verify the wrong
outcome with high confidence. This is most dangerous in financial, security,
production, and other domains where correctness depends on niche definitions
and authority that repository inspection alone cannot establish.

An unrestricted interview is not an acceptable fix. It can overwhelm the
user, invite invented context, and produce confirmation that is no longer bound
to the contract or repository state eventually started.

## Decision

Add `jstack_loop_goal_readiness` as a mandatory pre-start and material-revision
gate.

The gate:

1. accepts partial intake and returns the complete gap set;
2. emits no more than three prioritized blocking questions per round;
3. normalizes a structured, source-attributed, domain-aware `goal_context`;
4. records assumptions, open questions, and model-inferred material fields;
5. requires explicit exact-digest confirmation for ambiguity, inference,
   assumptions, sensitive domains, medium-or-higher risk, or L3 autonomy; and
6. issues a short-lived session-local receipt bound to the semantic contract,
   context, Git HEAD and fingerprint, policy, tool version, and revision base.

`jstack_loop_start` rejects a missing, stale, tampered, cross-session,
repository-mismatched, or contract-mismatched receipt. A material
`jstack_loop_revise` call requires a receipt bound to the loop ID and current
prior contract digest. Approval-only and retry/resume revisions may carry the
existing readiness decision when semantic fields do not change.

The additive `goalContext` and `goalReadiness` fields remain inside
`jstack.loop.contract.v1`. This preserves read compatibility with 0.4.0 state;
legacy loops need complete context and a fresh receipt before their first
material revision.

## Invariants

1. Readiness is not inferred from prompt length or model confidence.
2. Repository and runtime inspection precede user questions where practical.
3. The agent never fabricates user confirmation or hides inferred fields.
4. Blocking unknowns prevent receipt issuance.
5. Confirmation identifies one exact readiness digest and factual external
   reference.
6. Receipt issuance never authorizes implementation, protected paths, push,
   deployment, release, or policy weakening.
7. Goal readiness supplements rather than replaces QA, security, audit,
   review, human approval, and completion evidence.

## Rejected Alternatives

- Prompt-only intake guidance: advisory text cannot enforce start or revision.
- A fixed questionnaire: wastes user attention and does not adapt to domain or
  inspected evidence.
- Unlimited agent questions: creates interview loops without bounded progress.
- Silent model inference: hides ambiguity and can verify the wrong target.
- Persisting plaintext confirmation text: unnecessary sensitive data; the
  durable contract stores only its digest and assessment metadata.
- A new contract schema version: additive optional fields are sufficient and a
  version bump would make existing durable loops unreadable without migration.

## Consequences

Loop start now takes an additional bounded round when context is incomplete or
risk warrants confirmation. In return, execution mode, subagent staffing, and
acceptance evidence operate against a domain-specific target the user has
actually authorized. Receipts are intentionally short-lived and must be
reissued after MCP restart, repository drift, or semantic contract changes.
