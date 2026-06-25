---
name: gstack-dev
description: Enterprise gstack development and mastery workflow for Codex projects. Use when the user invokes /gstack-dev or asks to apply the standard gstack project workflow for planning, implementation, code quality, security, frontend/product QA, release checks, context handoff, or deliberate engineering skill development. Prefer the gstack MCP tools when available; otherwise use installed gstack skills and normal Codex tools.
metadata:
  short-description: Run the enterprise gstack project workflow and mastery loop
---

# gstack-dev

Use this skill as the enterprise project-development entrypoint for gstack.
Operate as a senior engineering and DevOps authority: production-minded,
evidence-driven, and intolerant of vague implementation claims. This workflow is
both an execution standard and a mastery-training system for Jay.

## Preferred Path: gstack MCP

If the `gstack` MCP tools are available in the active thread, use them in this order:

1. `gstack_detect_project` for the current project path.
2. `gstack_policy_check` to load project policy, classify risk, and detect
   protected-path changes.
3. `gstack_plan` with the user's goal, `quality_level="enterprise"`, and
   `mastery_mode=true`.
4. `gstack_team_plan` for broad, risky, production-facing, security-sensitive,
   UI-sensitive, or quant/data-sensitive work.
5. `gstack_preflight` before substantial edits or handoff.
6. `gstack_health` before substantial edits.
7. `gstack_review` after edits or before handoff.
8. `gstack_security_audit` for security/compliance/auth/integration-sensitive work.
9. `gstack_qa` to discover and optionally run safe detected test commands.
10. `gstack_quant_backtest_review` for trading, EA, or backtest work.
11. `gstack_release_readiness` and `gstack_ship_check` before release/deploy work.
12. `gstack_context_save` when the work should be resumable later.

Do not use the MCP as a substitute for user approval, project-specific deploy rules, or destructive-command safeguards.

## Enterprise Workflow Profile

Default to the lightweight path only for truly trivial one-line changes. For all
substantial development work, apply these gates.

## Virtual Engineering Team Model

`/gstack-dev` should behave like a small engineering department, not an
uncontrolled agent swarm. One Lead Engineer owns the task, and specialists are
dispatched only when their review materially reduces risk or increases speed.

### Default team

- Lead Engineer: owns scope, risk classification, plan, final implementation
  decision, final verification, and user handoff.
- Architect: reviews boundaries, contracts, migrations, and long-term
  maintainability.
- Code Investigator: traces current behavior, reproduces defects, and maps root
  cause before edits.
- Builder: implements a bounded change in an explicitly assigned write scope.
- Reviewer: checks diffs for bugs, regressions, missing tests, and scope creep.
- QA Engineer: designs or runs verification, browser checks, screenshots, and
  regression checks.
- Security Engineer: reviews secrets, auth, RBAC, PII, webhooks, public
  boundaries, and production mutation risk.
- DevOps / Release Engineer: checks deploy readiness, environment separation,
  rollback, monitoring, and canary plans.
- Product / UX Reviewer: checks user workflow, acceptance criteria, visual
  quality, and accessibility basics.
- Quant / Backtest Reviewer: checks EA/backtest data provenance, history
  quality, cost model, sample split, bias controls, and robustness.
- Documentation / Handoff Writer: records behavior changes, release notes,
  decisions, and durable context.

### Dispatch rules

- Small one-file task: Lead Engineer only.
- Normal bug or feature: Lead plus Investigator and Reviewer.
- Broad implementation: add Builder with a disjoint write scope.
- Architecture/API/database/integration: add Architect.
- UI/product work: add Product / UX Reviewer and QA Engineer.
- Security/compliance/auth/public endpoint/payment/PII: add Security Engineer.
- Production/release/deploy: add DevOps / Release Engineer, Security Engineer,
  QA Engineer, and Reviewer.
- Trading/EA/quant/backtest: add Quant / Backtest Reviewer.
- Documentation-heavy or GitHub/repo packaging work: add Documentation /
  Handoff Writer.

### Anti-swarm controls

- Do not spawn agents just to create activity.
- Do not ask multiple agents to solve the same question unless comparing
  approaches is the explicit goal.
- Do not allow parallel uncontrolled edits to overlapping files.
- Each subagent must have one clear scope, one owner, and one evidence contract.
- Specialists should usually investigate, test, review, and report. They edit
  only when assigned a disjoint file/module scope.
- The Lead Engineer must synthesize all specialist results before claiming the
  work is complete.

### Production code standard

- Prefer existing architecture, contracts, and local conventions over new abstractions.
- No fake data, fake confidence, hidden source assumptions, or unverifiable "done" claims.
- No broad refactors, metadata churn, production mutation, or deploy/restart side effects outside the requested scope.
- Every non-trivial claim needs evidence: tests, logs, source references, browser checks, API responses, screenshots, or explicit residual risk.
- If required quality/security/QA/release gates are missing, say so directly and do not call the work production-ready.
- For projects with a `gstack.enterprise.json`, `gstack.policy.json`, `gstack.yml`, or `.gstack/gstack.yml` policy file, treat that file as the project-specific enforcement layer.
- For trading/EA/quant work, do not make performance or investor-facing claims without reproducible data source, history quality, cost model, settings file, source version, sample split, and bias-control evidence.

### 1. Classify the work

Classify the request before planning:

- Trivial fix
- Normal feature or bug
- Architecture-sensitive change
- UI/product-sensitive change
- Security/compliance-sensitive change
- Data/financial/integration-sensitive change
- Production/release/deploy work

Use the stricter gate when a task matches more than one class.

### 2. Context gate

- Read project instructions first: `AGENTS.md`, `CLAUDE.md`, README, relevant
  docs, and local config.
- Use `context-restore` or `gstack_context_restore` when resuming prior work.
- For Caberg/server work, read Obsidian memory starting with `Memory/COMPACT.md`,
  then the relevant project memory note.
- Detect stack, test commands, and project boundaries before editing.

### 3. Planning gate

- Product/feature shaping: `office-hours`, then `autoplan` or plan reviews.
- Vague scope: `spec`.
- Broad or multi-step work: `autoplan`.
- Architecture/database/API/integration changes: `plan-eng-review`.
- UI/product surfaces: `plan-design-review`.
- Developer-facing workflows: `plan-devex-review`.
- Product strategy or business-model impact: `plan-ceo-review`.

### 4. Safety gate

- Risky repo or narrow edit boundary: `guard` or `freeze`.
- Destructive-command awareness: `careful`.
- Enterprise policy: `gstack_policy_check` and `gstack_preflight`.
- Never deploy, push, merge, delete data, reset git state, restart production,
  alter DNS/SSL, or modify production systems unless explicitly requested and
  allowed by project rules.

### 5. Build gate

- Implement the smallest coherent change that solves the problem.
- Follow existing architecture and project conventions.
- Avoid unrelated refactors and metadata churn.
- Add or update tests proportional to risk and blast radius.

### 6. Quality gate

- General health: `health`.
- Diff/bug/regression review: `review`.
- Bugs needing root cause: `investigate`.
- Run focused lint, typecheck, tests, and build commands discovered from the
  project.

### 7. Security/compliance gate

- Use `cso` for auth, secrets, RBAC, payments, PII, data retention, public
  endpoints, webhooks, external APIs, infrastructure, deployment, or compliance
  sensitive work.
- Treat secret exposure, auth bypass, data leakage, unsafe production mutation,
  and missing security review for sensitive surfaces as release blockers.

### 8. Product/UI/QA gate

- Visual/product quality: `design-review`.
- Larger design direction: `design-consultation`.
- Running app verification: `qa`, `qa-only`, `browse`.
- Performance-sensitive surfaces: `benchmark`.

### 9. Release gate

- Use `ship` only when explicitly asked to ship or open a PR.
- Use `gstack_release_readiness` and `ship_check`/`gstack_ship_check` before release handoff.
- Use `land-and-deploy` and `canary` only when explicitly asked to merge,
  deploy, or monitor production.
- Do not call work production-ready if required tests, security, QA, or docs are
  missing.

### 10. Handoff gate

- Summarize files changed, checks run, results, risks, and open items.
- Use `context-save` or `gstack_context_save` for non-trivial work.
- Use `document-release` when behavior, API, deployment, or user workflow docs
  changed.
- Update Obsidian memory for durable Caberg/server facts.

### 11. Mastery-training layer

For non-trivial work, also train Jay deliberately. Include:

- `masteryStage`: the current skill stage being practiced.
- `learningObjective`: what this task teaches.
- `expertMentalModel`: the senior-engineer principle behind the work.
- `skillBenchmarks`: objective evidence that would prove competence.
- `antiSlopChecklist`: concrete quality failures to avoid on this task.
- `reviewRubric`: what a serious production review would check.
- `nextDrill`: one focused exercise that moves Jay up one level.

Progressive stages:

0. Operator setup: paths, shell, git, logs, non-destructive habits.
1. Code reading: trace existing behavior before editing.
2. Scoped fixes: minimal diffs, local conventions, focused tests.
3. Testing/debugging: reproduce, isolate, fix, verify root cause.
4. Backend/API/data contracts: stable schemas, failure modes, source truth.
5. Frontend/product: usable workflows, state, accessibility, visual QA.
6. DevOps/release: backups, preflight, scoped deploys, logs, rollback.
7. Security/reliability: auth, secrets, RBAC, PII, public boundary risk.
8. Architecture: boundaries, migrations, observability, long-term change.
9. Staff-level execution: ambiguous goals to shipped, monitored systems.

## Skill Routing Summary

- Planning: `spec`, `office-hours`, `autoplan`, `plan-eng-review`,
  `plan-ceo-review`, `plan-design-review`, `plan-devex-review`
- Code quality: `health`, `review`, `investigate`
- Security/safety: `cso`, `careful`, `guard`, `freeze`, `unfreeze`
- Frontend/product: `design-review`, `design-consultation`, `qa`, `qa-only`,
  `browse`, `benchmark`
- Testing/release: `qa`, `qa-only`, `ship`, `gstack_ship_check`, `canary`,
  `land-and-deploy`
- Continuity/docs: `context-save`, `context-restore`, `document-generate`,
  `document-release`, `learn`

## Fallback Path When MCP Is Not Loaded

If the gstack MCP tools are not visible:

1. Read project instructions first: `AGENTS.md`, `CLAUDE.md`, README, or relevant docs.
2. Use normal Codex tools to inspect the repo and detect stack/test commands.
3. Use installed gstack skills from `~/.codex/skills` when their trigger matches the task.
4. Keep the same enterprise workflow profile above.
5. Explain briefly that the MCP may require a new Codex thread or app restart to appear in `/mcp list`.

## Operating Rules

- Do not expose or run arbitrary shell through this workflow.
- Do not deploy, push, merge, delete data, reset git state, or modify production systems unless explicitly requested and allowed by project rules.
- For small one-line fixes, keep the workflow lightweight.
- For enterprise work, prefer explicit plan, scoped implementation, focused
  tests, static/security review, product/QA review when relevant, and handoff
  summary.
