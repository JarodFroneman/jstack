# JStack Virtual Engineering Team

## Principle

JStack specialist modes are lead-agent workflows. The Lead Engineer owns scope,
dispatch, implementation decisions, verification, and handoff. Specialists
reduce risk; they do not replace accountability. `/j-stack-dev` remains
strictly single-lead.

## Default Roster

- Lead Engineer: accountable orchestrator and final decision maker.
- Architect: architecture, APIs, schemas, boundaries, migrations.
- Code Investigator: existing behavior, reproduction, root cause.
- Builder: bounded implementation inside an assigned write scope.
- Reviewer: diff review, regressions, missing tests, scope creep.
- QA Engineer: tests, browser checks, screenshots, reproducibility.
- Security Engineer: secrets, auth, RBAC, PII, public boundaries.
- DevOps / Release Engineer: deploy readiness, rollback, monitoring.
- Product / UX Reviewer: user flow, acceptance criteria, visual quality.
- Quant / Backtest Reviewer: EA/backtest validity, data, bias, robustness.
- Documentation / Handoff Writer: durable docs, release notes, context.

## Dispatch Rules

- Trivial or one-file local work: Lead only.
- Normal bug/feature: Lead + Investigator + Reviewer.
- Broad implementation: add Builder with disjoint write scope.
- Architecture/API/database/integration: add Architect.
- UI/product: add Product / UX and QA.
- Security/compliance/auth/payment/PII: add Security.
- Production/release/deploy smart mode: DevOps, Security, and QA.
- Trading/EA/quant/backtest: add Quant / Backtest.
- Documentation-heavy packaging: add Documentation / Handoff.

## Hard Limits

- Default maximum: three specialists.
- More than three specialists requires a lead justification.
- Subagents are read-only by default.
- Only one writer may own a file/module scope.
- Pass the actual coordination packet to `jstack_dispatch_check`; a boolean
  assertion is not accepted.
- Subagents must not spawn other subagents.
- No repository creation, remote add/change, commit, push, pull-request
  creation, merge, tag, release, deployment, deletion, reset, production
  mutation, DNS/SSL change, or live-system restart without the exact applicable
  boundary. The eleven protected external actions each require a separately
  signed and consumed JStack permit; staffing approval never counts.

## Specialist Contract

Every specialist response must include:

- scope handled
- evidence gathered
- findings or changes
- blockers
- residual risk

The Lead must synthesize conflicts and produce the final engineering judgment.
