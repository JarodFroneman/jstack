# ADR 0032: Operating Profiles Set Governance Floors, Not Agent Topology

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS

## Context

Solo developers need low ceremony, while commercial and enterprise work need
stronger review, evidence, and policy. Conflating those needs with command or
team size would either burden simple work or allow a small-team selection to
bypass safety controls.

## Decision

Add three ordered profiles: `solo`, `professional`, and `enterprise`.
Professional is the recommended commercial default. A profile determines the
minimum governance and evidence controls; an operating mode independently
determines physical-agent topology.

Profile selection follows `may-strengthen-never-weaken`. Users and policy may
select a stronger profile. A lower profile cannot remove controls mandated by
risk, production, task authority, or enterprise policy. Solo therefore remains
subject to mandatory floors for destructive work, auth, secrets, cryptography,
payments, financial systems, migrations, sensitive data, and release actions.

Profiles are versioned JStack policy data. They do not import gstack state or
configuration, grant authority, or silently change existing projects.

## Rejected Alternatives

- Infer governance from agent count: rejected because topology is not risk.
- Make Enterprise the default for every task: rejected as disproportionate.
- Allow a per-prompt `solo` override of risk controls: rejected as unsafe.

## Consequences

Later stages need explicit selection precedence, project configuration,
feature-flagged migration, and tests proving monotonic control strength.
