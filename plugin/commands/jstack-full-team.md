---
description: Run JStack with the full 11-role engineering team
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `full-team`.

The user invoked `/jstack-full-team`, which is explicit approval to deploy the
full JStack specialist team when multi-agent tools are available.

Resolve learning mode first: use an explicit `off`, `coach`, or
`assessment` request; otherwise use `embedded`. Pass that resolved value to
every planning call.

Call `jstack_runtime_status` before project tools. A successful call proves the
MCP is mounted. Use `jstack_detect_project` and branch on `evidenceMode`. For
`artifact-only`, state `MCP mounted; project binding is artifact-only.`, keep
team planning and dispatch validation, do not call tools listed in
`blockedTools`, and gather direct artifact evidence without claiming JStack
receipts or release certification. Only use the MCP fallback when
`jstack_runtime_status` itself is unavailable or unreachable; never relabel a
Git requirement or failed gate as an MCP attachment failure.

Use the full 11-role roster:

1. Lead Engineer
2. Architect
3. Code Investigator
4. Builder
5. Reviewer
6. QA Engineer
7. Security Engineer
8. DevOps / Release Engineer
9. Product / UX Reviewer
10. Quant / Backtest Reviewer
11. Documentation / Handoff Writer

The Lead Engineer remains accountable. Specialists are read-only by default.
Builder is the only specialist that may edit implementation files, and only with
an explicitly assigned disjoint write scope. Documentation / Handoff Writer may
edit docs only when assigned.

If platform concurrency limits prevent all specialists from running at once,
dispatch them in waves while preserving the full-team evidence contract.

Full team means complete professional coverage, not uncontrolled concurrency.
Before dispatching, create a coordination packet with:

- `goal`: exact objective
- `riskClass`: array of every matched risk class
- `mode`: `full-team`
- `rolesUsed`: all 11 roles and reasons
- `rolesNotUsed`: empty because all 11 are accounted for
- `readWritePermissions`
- `fileOwnershipMap`
- actual `capabilityPlan` and exact per-role `capabilityIds`
- `evidenceContract`
- `conflictRule`
- `stopConditions`
- `verificationGate`
- `handoffGate`

Use `jstack_team_plan` with `team_mode="full-team"` and
`jstack_dispatch_check` with `team_mode="full-team"` and
the actual `coordination_packet` object when available. Also use
`jstack_plan(team_mode="full-team", learning_mode=resolved_learning_mode)`. The MCP
plans and validates the team; platform multi-agent tools perform real dispatch.
If multi-agent tools are unavailable, write `No subagents deployed:` and give
the concrete reason. Retain `team_mode="full-team"` in planning and apply
the full-team evidence rubric while one Lead performs the actual work.

When concurrency would create noise, dispatch the full team in waves:

1. Discovery: Architect, Code Investigator, Product/UX, and Quant. Every role
   returns bounded evidence, even when its finding is "not applicable".
2. Build: Builder only after Lead approval of scope.
3. Review: Reviewer, QA, Security, DevOps, Documentation.
4. Synthesis: Lead reconciles findings, verifies, and hands off.

Every role receives only its routed capability subset. Capabilities add method,
required evidence, stop conditions, audit domains, and loop controls while
inheriting core-role permissions; they never grant tools, writes, delegation,
approvals, or release authority. Every wave returns
`jstack.specialist.result.v1` plus metadata-only
`jstack.specialist.telemetry.v1` per role, including Lead. Call
`jstack_specialist_result` for all 11 exact assignments and then
`jstack_specialist_handoff_check`. Raw prompts, messages, tool arguments,
command/model output, source contents, and secrets are forbidden. Missing,
stale, partial, capability-drifted, permission-unsafe, or contradictory receipt
sets block handoff until explicitly reconciled with evidence.

For an active full-team loop, pass the current validated
`specialist_handoff_receipt` to every checkpoint and finalization.

For production/release work, the Lead declares `core` plus every applicable
surface on the clean integrated candidate. Existing Security, QA, DevOps,
Product, Architect, Reviewer, Documentation, and accountable human owners
collect the selected launch evidence; only the Lead registers and finalizes
it. Missing or failed blocker/required evidence blocks synthesis. Public-web,
commercial, payment, and regulated-data profiles also require a release-profile
audit by default. Full-team approval remains staffing authority only.

JStack never generates approval challenges, tokens, signing commands, or
terminal approval steps. Only the accountable Lead may perform repository,
Git, provider, deployment, or production actions, and only within the user's
explicit request plus normal Codex/provider permissions. Specialists remain
unable to perform those actions. Full-team staffing approval, readiness, and
handoff do not widen task scope or bypass the host's ordinary safety controls.

Finish in the order outcome, evidence, residual risk, then an optional
three-line mastery capsule. Do not emit eleven role-by-role lessons.
