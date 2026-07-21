# JStack Agent Coordination Protocol

## Core Rule

Full team means complete professional coverage, not uncontrolled concurrency.
The Lead Engineer owns the task. Specialists reduce blind spots. Builder owns
implementation only inside assigned write scopes.

## Execution Modes

### Single Lead

Use for small, low-risk, one-file, or clearly bounded work.

- Command: `/j-stack-dev`
- Agents: Lead Engineer only
- Edits: Lead Engineer only
- Required output: scope, change, verification, residual risk

### Smart Subagents

Use for normal professional work where two or three specialists materially
reduce risk.

- Command: `/jstack-subagents`
- Agents: Lead Engineer plus two or three specialists
- Edits: Lead Engineer or one assigned Builder
- Required output: role table, evidence, conflicts, verification, residual risk

### Full Team

Use for major, ambiguous, production-sensitive, security-sensitive,
architecture-sensitive, quant/data-sensitive, or explicitly requested full-team
work.

- Command: `/jstack-full-team`
- Agents: full 11-role roster as coverage
- Concurrency: dispatch in waves when needed
- Edits: one Builder by default; more only with disjoint write scopes
- Required output: coordination packet before execution and synthesis packet
  before completion

## Coordination Packet

Before deploying several agents or using full-team mode, the Lead Engineer must
define:

| Field | Required Content |
| --- | --- |
| Goal | The user objective in one sentence |
| Risk class | Trivial, normal, architecture, UI/product, security, data/financial, release |
| Mode | single-lead, smart-subagents, or full-team |
| Roles used | Exact agents used and why each is necessary |
| Roles not used | Any skipped specialists and why |
| Read/write permissions | Who may edit and who is read-only |
| File ownership map | Path or module ownership for every editing agent |
| Evidence contract | What each specialist must return |
| Capability plan | Exact versioned role-to-capability assignments from JStack planning |
| Conflict rule | How contradictory findings are resolved |
| Stop conditions | Conditions that force pause/escalation |
| Verification gate | Tests, checks, QA, screenshots, logs, or reports required |
| Handoff gate | Final summary shape and residual-risk requirements |

`jstack_dispatch_check` receives this actual object, including the unmodified
`capabilityPlan` and exact per-role `capabilityIds` from planning. A boolean
assertion that a packet exists is invalid. The MCP recomputes routing and never
claims to spawn agents; Codex platform tools perform dispatch and collection.

## Role Permission Defaults

| Role | Default Mode | Edit Permission |
| --- | --- | --- |
| Lead Engineer | Orchestrator | May edit |
| Architect | Specialist | Read-only |
| Code Investigator | Specialist | Read-only |
| Builder | Specialist | May edit only assigned scope |
| Reviewer | Specialist | Read-only |
| QA Engineer | Specialist | Read-only |
| Security Engineer | Specialist | Read-only |
| DevOps / Release Engineer | Specialist | Read-only |
| Product / UX Reviewer | Specialist | Read-only |
| Quant / Backtest Reviewer | Specialist | Read-only |
| Documentation / Handoff Writer | Specialist | Docs only when assigned |

## File Ownership Rules

1. No two editing agents may own the same file or module.
2. Shared files require Lead Engineer ownership or explicit serialization.
3. Specialists may not edit outside their assigned write scope.
4. A file ownership conflict blocks dispatch until resolved.
5. If the scope cannot be split cleanly, use one Builder.
6. Reject absolute paths, traversal, repository-root scopes, and ancestor/glob
   overlaps such as `src` versus `src/api`.

## Evidence Contract

Every specialist must return:

- scope handled
- files, commands, screenshots, logs, reports, or data reviewed
- findings ordered by severity or importance
- explicit blockers
- residual risk
- recommended next action

The response uses `jstack.specialist.result.v1` and must include every evidence
kind required by the role's routed capabilities. Each role also submits
`jstack.specialist.telemetry.v1`: bounded IDs, timing, status, tool
names/statuses, evidence references, and optional counts with
`rawContentStored: false`. Do not submit prompts, messages, tool arguments,
model output, arbitrary logs, hidden reasoning, or secret values.

`jstack_specialist_result` validates and signs each role's current result.
Before synthesis, `jstack_specialist_handoff_check` must validate the complete
receipt set. It fails closed on missing or stale roles, routing drift,
unauthorized changes, failed results, or unresolved contradictions.

## Conflict Resolution

1. Evidence beats opinion.
2. Reproduction beats speculation.
3. Project rules beat generic best practice.
4. Safety gates beat speed.
5. The Lead Engineer makes the final decision and documents unresolved risk.

Contradictory findings use a shared `resolutionKey`. The Lead may resolve them
only through the handoff validator with a decision, rationale, and evidence
references. An unresolved contradiction blocks the signed handoff.

## Stop Conditions

Pause and escalate before continuing when:

- an exact signed action authorization is missing
- repository, Git, release, deployment, or production mutation is implied by
  broad task, staffing, phase, or remediation approval
- secrets or credentials are exposed
- agents disagree on a release blocker
- tests fail for an unclear reason
- file ownership overlaps
- the task scope has expanded beyond the user request
- the strategy or implementation would be misleading without more evidence

## Full-Team Wave Pattern

When full 11-agent concurrency is too much, dispatch in waves:

1. Discovery wave: Architect, Code Investigator, Product/UX or Quant when
   relevant.
2. Build wave: Builder only after the Lead approves scope.
3. Review wave: Reviewer, QA, Security, DevOps, Documentation.
4. Synthesis wave: Lead reconciles evidence, resolves conflicts, verifies, and
   hands off.

## Anti-Slop Standard

Do not accept output that:

- lacks file references or runtime evidence
- makes broad claims without proof
- edits outside assigned scope
- duplicates another specialist without purpose
- ignores project instructions
- hides skipped checks
- calls work production-ready without tests, security, QA, and release gates
- optimizes for agent activity over verified outcomes
