# ADR 0029: Specialist Identity Is Separate From Canonical Role Authority

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0005](0005-specialist-capability-protocol.md)

## Context

The target organization needs recognizable titles such as Frontend Engineer,
Identity & Access Engineer, and Security Auditor. JStack currently has eleven
canonical roles whose permissions and independence behavior are already part
of public contracts. Treating every title as a new role would multiply
authority classes and allow persona wording to become permission logic.

## Decision

A `Specialist` is a human-facing expertise record. A `CanonicalRole` is an
authority class. Every specialist references exactly one canonical role and
one or more capabilities. Specialists contain activation and independence
criteria but no permission override.

The canonical role supplies the maximum authority ceiling. Capabilities may
only narrow or apply that authority. A specialist is assigned to a physical
agent only in a `TeamPlan`; specialist identity never implies a separate agent.

The eleven current role IDs remain the initial closed role vocabulary:
`lead`, `architect`, `investigator`, `builder`, `reviewer`, `qa`, `security`,
`devops`, `product`, `quant`, and `docs`.

## Rejected Alternatives

- One role per job title: rejected due to authority proliferation.
- Free-form personas with prompt-only permissions: rejected because they are
  not deterministic or auditable.
- Specialist equals physical agent: rejected because it wastes context and
  breaks bounded execution modes.

## Consequences

JStack can expose a rich organization while preserving a small auditable
permission model. Catalog validation and team composition must check every
specialist-to-role reference and independence constraint.
