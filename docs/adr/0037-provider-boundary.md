# ADR 0037: Providers Perform Bounded Work But Never Become Authority

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0006](0006-external-action-authorization-boundary.md)

## Context

Browser, scanner, Git, host, deployment, model, device, and artifact runtimes
can add value but have different dependencies, side effects, state, and egress.
Calling their commands directly from adapted prompts would bypass JStack's
permission, evidence, and policy boundaries.

## Decision

All Class B execution uses a versioned JStack Provider contract. A provider
declares runtime, optionality, availability behavior, maximum effects,
authorization prerequisites, input trust, bounded state, telemetry, timeout,
resource limits, and evidence contracts.

Provider requests are constructed without unsafe shell concatenation and are
validated before dispatch. Returned artifacts are treated as untrusted data,
validated, source-labelled, and bound to project, candidate, policy, provider,
and freshness before use. Missing runtimes return `UNAVAILABLE` or
`UNSUPPORTED`; no fallback may fabricate evidence.

A provider is not an orchestrator, cannot select policy, cannot expand role or
user authority, cannot self-authorize, and cannot turn evidence into approval.
Its declared effects describe technical capability, not permission.

## Rejected Alternatives

- Direct CLI calls embedded in skills: rejected as an authority bypass.
- One omnipotent provider: rejected for least privilege and auditability.
- Treat provider success as JStack PASS: rejected because evidence still needs
  independent validation and binding.

## Consequences

Optional runtimes remain isolated and replaceable. Each provider costs a thin
adapter, schema validation, security review, limits, and negative tests.
