# JStack Virtual Engineering Team

## Principle

JStack is a lead-agent workflow. The Lead Engineer owns scope, dispatch,
implementation decisions, verification, and handoff. Specialists reduce risk;
they do not replace accountability.

## Command Modes

- `/j-stack-dev`: Lead Engineer only. Use another command when subagents are
  wanted.
- `/jstack-subagents`: Lead Engineer plus the right specialist team, normally
  2-3 specialists.
- `/jstack-full-team`: full 11-role professional coverage, usually dispatched
  in waves rather than as uncontrolled concurrency.

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
- Phase, milestone, project, or broad roadmap work: Lead + Investigator +
  Reviewer, plus QA when verification risk is meaningful.
- Broad implementation: add Builder with disjoint write scope.
- Architecture/API/database/integration: add Architect.
- UI/product: add Product / UX and QA.
- Security/compliance/auth/payment/PII: add Security.
- Production/release/deploy: DevOps, Security, and QA in smart mode; full-team
  mode adds complete review coverage.
- Trading/EA/quant/backtest: add Quant / Backtest.
- Documentation-heavy packaging: add Documentation / Handoff.

## Hard Limits

- `/jstack-subagents` should normally use two or three specialists.
- `/jstack-full-team` must account for all 11 roles, but does not need to run
  every role concurrently.
- Full team means complete professional coverage, not uncontrolled concurrency.
- Subagents are read-only by default.
- Only one writer may own a file/module scope.
- Subagents must not spawn other subagents.
- No deploy, push, merge, deletion, reset, production mutation, DNS/SSL change,
  or live-system restart without explicit user approval.

## Specialist Contract

Every specialist response must include:

- scope handled
- evidence gathered
- findings or changes
- blockers
- residual risk

The Lead must synthesize conflicts and produce the final engineering judgment.

## Coordination Packet

Before deploying several specialists or using `/jstack-full-team`, the Lead
must define:

- goal
- risk class
- execution mode
- roles used and why
- roles skipped and why
- read/write permissions
- file ownership map
- evidence contract
- conflict rule
- stop conditions
- verification gate
- handoff gate

Pass the actual packet object to `jstack_dispatch_check`. The MCP validates
the plan; platform multi-agent tools perform real dispatch.

## Full-Team Wave Pattern

1. Discovery wave: Architect, Code Investigator, Product/UX or Quant when
   relevant.
2. Build wave: Builder only after the Lead approves the write scope.
3. Review wave: Reviewer, QA, Security, DevOps, Documentation.
4. Synthesis wave: Lead reconciles findings, resolves conflicts, verifies, and
   hands off.
