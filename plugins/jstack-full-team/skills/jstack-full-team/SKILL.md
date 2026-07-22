---
name: jstack-full-team
description: Full 11-role JStack team workflow. Use when the user invokes /jstack-full-team or explicitly asks to deploy the full JStack team.
metadata:
  short-description: Deploy the full JStack team
---

# JStack Full Team

Treat this command as explicit user approval to deploy the full JStack team when multi-agent tools are available.

Full team means complete professional coverage, not uncontrolled concurrency.
The Lead Engineer may dispatch the full team in waves when that is safer or
clearer.

Full roster:

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

Operating rules:

1. The Lead Engineer owns final scope, synthesis, implementation decisions, verification, and handoff.
2. Specialists are read-only by default.
3. Builder may edit only inside an explicitly assigned disjoint write scope.
4. Documentation / Handoff Writer may edit docs only when assigned.
5. If concurrency limits prevent all specialists from running at once, dispatch them in waves.
6. Before dispatch, require a coordination packet.
7. Pass the actual packet to `jstack_dispatch_check` and call
   `jstack_plan` with `team_mode="full-team"` and
   the resolved learning mode: explicit `off`, `coach`, or `assessment`,
   otherwise `embedded`.
8. The MCP plans and validates; platform multi-agent tools perform actual
   dispatch, collection, and closure.
9. Call `jstack_runtime_status` before project tools. A successful call proves
   the MCP is mounted. Use `jstack_detect_project` and branch on
   `evidenceMode`. For `artifact-only`, state
   `MCP mounted; project binding is artifact-only.`, keep team planning and
   dispatch validation, do not call tools listed in `blockedTools`, and gather
   direct artifact evidence without claiming JStack receipts or release
   certification. Only use the MCP fallback when `jstack_runtime_status`
   itself is unavailable or unreachable; never relabel a Git requirement or
   failed gate as an MCP attachment failure.

Coordination packet:

- `goal`
- `riskClass` array
- `mode: full-team`
- `rolesUsed` (all 11) and empty `rolesNotUsed`
- `readWritePermissions` and `fileOwnershipMap`
- actual `capabilityPlan` and exact per-role `capabilityIds`
- `evidenceContract`, `conflictRule`, and `stopConditions`
- `verificationGate` and `handoffGate`

Full-team wave pattern:

1. Discovery: Architect, Code Investigator, Product/UX, and Quant.
2. Build: Builder only after Lead approval of scope.
3. Review: Reviewer, QA, Security, DevOps, Documentation.
4. Synthesis: Lead reconciles evidence, resolves conflicts, verifies, and hands off.

Every role receives only its routed capability subset. Capability packs add
methods, evidence requirements, stop conditions, audit domains, and loop
controls while inheriting the core role's permissions; they never grant tools,
writes, delegation, approvals, or release authority. Every wave returns one
`jstack.specialist.result.v1` plus metadata-only
`jstack.specialist.telemetry.v1` per role, including a Lead result. The Lead
calls `jstack_specialist_result` for all 11 exact role/capability assignments,
then `jstack_specialist_handoff_check`. Do not retain raw prompts, messages,
tool arguments, command/model output, source contents, or secrets. Missing,
stale, partial, permission-unsafe, capability-drifted, or contradictory receipt
sets block handoff until explicitly reconciled with evidence.

If multi-agent tools are unavailable, state `No subagents deployed:` with the
concrete reason. Retain `team_mode="full-team"` in planning and apply its
evidence rubric while one Lead performs the work.

When an active JStack loop supplies a `loopId`, keep `team_mode="full-team"`
fixed for that contract and execute only the current wave-bounded iteration.
Pass the current validated `specialist_handoff_receipt` to every checkpoint
and finalization; the loop owns convergence and terminal status.

For production/release work, the Lead declares `core` plus every applicable
product surface with `jstack_launch_assess` on the clean integrated candidate.
Route selected controls through the existing roster: Security, QA, DevOps,
Product, Reviewer, Architect, and Documentation collect their bounded evidence;
accountable humans own legal and merchant decisions. The Lead alone registers
and finalizes the exact selection. Missing, stale, failed, incomplete, or
drifted blocker/required launch evidence blocks synthesis. Public-web,
commercial, payment, and regulated-data profiles also require a current
release-profile audit receipt by default. Full-team staffing is not launch or
external-action authority.

Default to local-only. Full-team approval authorizes staffing only. Repository
creation, remote add/change, commit, push, pull-request creation, merge, tag,
release, deployment, and production mutation each require a separate exact
signed one-time JStack external-action permit. Only the Lead may perform
challenge -> human signature outside Codex -> authorize -> fresh provider
observation -> consume, followed by one exact operation before expiry. No
specialist may request, sign, consume, or exercise this authority, and no broad
verb, wave/phase/remediation approval, readiness, handoff, shell, or provider
path may substitute for or bypass it.
