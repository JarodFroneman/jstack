# ADR 0031: Full Team Means Complete Function Coverage, Not A Fixed Roster

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Depends on: [ADR 0030](0030-team-composer.md)

## Context

`/jstack-full-team` currently exposes a fixed eleven-role roster. That is easy
to understand but expensive for small work and incomplete for IAM, browser QA,
accessibility, supply-chain, or other specialized boundaries. The product
specification defines Full Team by material function coverage and mandatory
independence instead of employee count.

## Decision

Full Team uses the Team Composer and represents every materially required
function. Substantial implementation normally includes Lead, appropriate
Builder coverage, independent Reviewer, and QA. It adds Product, Design,
Security, IAM, Data, Quant, SRE, Browser QA, Accessibility, Performance,
Supply Chain, or Release only when task facts, risk, or policy require them.

Logical specialist coverage and physical-agent count remain separate. Multiple
compatible specialists may share one physical agent, except where independence
requires separation. Every omitted department receives a reason.

The migration preserves the command name and additive public response fields.
The fixed roster may remain as a temporary compatibility view, but it cannot
remain the composition source of truth.

## Rejected Alternatives

- Always dispatch eleven or more agents: rejected for cost and coordination.
- Let users disable mandatory independent functions: rejected because modes
  and preferences cannot weaken risk floors.
- Rename the command: rejected as unnecessary compatibility breakage.

## Consequences

Full Team becomes proportionate and domain-aware. Historical tests that equate
the command with eleven active roles require additive migration and new
function-coverage assertions before behavior changes.
