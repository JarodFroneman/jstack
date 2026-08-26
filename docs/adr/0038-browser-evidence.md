# ADR 0038: Browser Runtime Produces Candidate-Bound Evidence

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Depends on: [ADR 0037](0037-provider-boundary.md)
- Extends: [ADR 0023](0023-product-interface-system.md) and
  [ADR 0027](0027-product-ui-motion-enforcement.md)

## Context

Browser QA is a high-value gstack capability, but JStack cannot equate browser
automation with source authority or trust screenshots and console output that
are not bound to the exact candidate. Browser content may also contain prompt
injection, secrets, malicious downloads, and poisoned instructions.

## Decision

Expose browser work only through an optional Provider contract. A request
specifies authorized routes, scenarios, viewports, interactions, network
policy, time and byte budgets, and evidence requirements. Browser content is
data, never an instruction.

Evidence records candidate/build identity, route, viewport, interaction
sequence, expected and observed states, screenshot references, console and
permitted network observations, accessibility observations, timing,
truncation, and provider failure. JStack verifies schema, safe paths, digests,
completeness, provenance, candidate binding, and freshness before issuing any
receipt.

The initial provider is local-only and excludes tunnels, silent cookie import,
downloads, source writes, Git writes, deployment, and production mutation.
QA findings return to an authorized Builder through a separate handoff.

## Rejected Alternatives

- Trust a browser transcript: rejected because it is unbound prose.
- Embed a mandatory browser runtime in core: rejected for dependency and host
  compatibility reasons.
- Allow browser QA to fix defects automatically: rejected because QA is not the
  Builder.

## Consequences

JStack can gain reproducible runtime evidence while keeping browser authority
narrow. Honest measurement remains a declared producer trust limitation.
