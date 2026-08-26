# ADR 0033: Risk Floors Are Deterministic And Non-Lowerable

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0009](0009-launch-assurance-v2.md)

## Context

Task risk must control minimum expertise, independence, evidence, and action
gates. A selected mode, profile, specialist, capability, or upstream method
must not be able to under-classify authentication, migrations, destructive
operations, financial logic, or production changes.

## Decision

Use the ordered risk classes `trivial`, `normal`, `elevated`, `high`, and
`production`. Deterministic repository and task signals establish a minimum.
Policy and an explicitly stronger user selection may raise it; no downstream
component may lower it.

At minimum: ordinary bounded feature work requires Builder and QA coverage;
external providers and architectural cross-cuts require architecture and QA;
auth requires IAM/AppSec independence; financial calculations require Quant,
review, and regression evidence; production requires release assurance and
separate explicit action authority.

Unknown material high-risk facts fail closed into clarification, review, or a
stronger floor. Risk classification is source-attributed and bound into the
TeamPlan. It grants no side-effect authority.

## Rejected Alternatives

- Model confidence alone: rejected because it is non-deterministic.
- User-selected profile as a risk override: rejected because preference cannot
  weaken a policy floor.
- Treat every task as high risk: rejected as unusable and costly.

## Consequences

Routing remains proportional while sensitive boundaries are deterministic.
Later policy tables need precedence, monotonicity, and adversarial bypass tests.
