# ADR 0028: JStack Remains The Sole Governance Kernel

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0005](0005-specialist-capability-protocol.md),
  [ADR 0006](0006-external-action-authorization-boundary.md), and
  [ADR 0010](0010-adaptive-context-gate.md)

## Context

JStack already owns prompt and context readiness, task-mode preservation,
policy, risk classification, roles, capabilities, audit, evidence, persistent
programs, release assurance, and action authority. gstack contains useful
methods and optional runtimes, but also has its own routing, state, installer,
updater, memory, shipping, and deployment behavior. Importing both control
planes would create contradictory authority and stale parallel state.

## Decision

JStack is the only governance and orchestration kernel. All adapted methods,
specialists, providers, evidence, and external actions enter through JStack
contracts and remain subordinate to JStack policy and host permissions.

The existing Prompt Compiler and Context Readiness gates remain intake owners.
Loop and Program remain durable-work owners. Canonical roles remain permission
owners. JStack audit, Product Interface, launch, and evidence contracts remain
their domain owners. The MCP entrypoint is a protocol adapter, not a second
place to accumulate integration logic.

Upstream content is untrusted data unless it is an explicitly authorized
instruction surface. No upstream skill, hook, config, state file, provider,
receipt, or generated host copy can override the user, host policy, or JStack
policy floor.

## Rejected Alternatives

- Merge the two repositories: rejected because it duplicates governance,
  dependencies, state, and release authority.
- Route between JStack and gstack control planes: rejected because the route
  itself cannot make contradictory policy and receipts safe.
- Let providers self-govern their permissions: rejected because technical
  capability is not authority.

## Consequences

The integration gains selected value without a second source of truth. Some
upstream workflows must be split, re-expressed, or rejected. Existing JStack
commands, permission controls, and receipt semantics remain authoritative.
