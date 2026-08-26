# ADR 0034: Scope Strategy Resolves Completion Bias Without Expanding Authority

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS

## Context

JStack favors the smallest coherent change, while some gstack methods favor
broad completion. Applying either preference universally causes under-built
greenfield work or risky adjacent cleanup in incidents and sensitive systems.

## Decision

Add three explicit strategies:

- `MINIMAL`: smallest coherent change and no adjacent cleanup;
- `BALANCED`: complete the requested feature, required tests, edge cases,
  documentation, and necessary integration without unrelated redesign;
- `COMPLETE`: complete an explicitly approved broad or greenfield surface.

Balanced is the professional default. Minimal is preferred for incidents,
security fixes, sensitive systems, migrations, and regulated work. Complete
requires an explicit broad goal and preserves all non-goals.

Scope strategy never changes task mode or action authority. It cannot turn a
plan into implementation, diagnosis into remediation, build into deployment,
or readiness into release. Material expansion returns to Prompt Compilation
and Context Readiness for a new approved contract.

## Rejected Alternatives

- Import gstack's completion bias unchanged: rejected for scope escalation.
- Always-minimal behavior: rejected for approved greenfield and redesign work.
- Free-form scope prose only: rejected because routing cannot enforce it.

## Consequences

The system can be thorough within a bounded goal. Later stages need defaulting,
invalidation, and tests for non-goal and task-mode preservation.
