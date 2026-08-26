# ADR 0030: Deterministic Team Composer Produces A Non-Authorizing TeamPlan

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Depends on: [ADR 0029](0029-specialist-vs-canonical-role.md)

## Context

The operating mode determines execution topology, while repository surfaces,
risk, policy, domain, independence, providers, and budgets determine required
expertise. Fixed rosters over-dispatch trivial work and still miss specialized
high-risk functions.

## Decision

Add one JStack-owned Team Composer. It consumes only approved Prompt Compiler
and Context Readiness bindings plus verified repository facts, task mode,
risk, profile, operating mode, scope strategy, policy, provider availability,
and bounded resource budgets.

It deterministically emits `jstack.team-plan.v1` with departments,
specialists, canonical roles, capabilities, physical-agent grouping, read and
write scopes, independence, providers, evidence, selection reasons, omitted
department reasons, limits, and a contradiction-resolution owner.

Composition is fail-closed for unknown IDs, invalid catalog references,
unsatisfied risk floors, impossible independence, scope/role conflicts, or
agent counts above the selected mode. Stable inputs produce a stable semantic
plan. The plan is descriptive and constraining; `authorityEffect` remains
`none` and no receipt may turn it into side-effect approval.

## Rejected Alternatives

- Model-only roster selection: rejected because safety floors and repeatability
  cannot depend on prose.
- Fixed team per command: rejected because expertise is task-dependent.
- Provider-selected team: rejected because a provider cannot orchestrate.

## Consequences

Later implementation needs versioned catalogs, deterministic matching,
referential-integrity validation, explicit tie-breaking, and negative tests.
The Lead remains the coordination and contradiction-resolution authority.
