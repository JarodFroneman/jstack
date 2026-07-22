---
description: Run JStack with the right specialist subagent team
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `smart-subagents`.

The user invoked `/jstack-subagents`, which is explicit approval to deploy
subagents for this task when multi-agent tools are available.

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

Use the Lead Engineer plus the right specialist team, normally 2-3 specialists:

- For normal feature/bug work: Code Investigator + Reviewer.
- For phase/milestone/project work: Code Investigator + Reviewer, plus QA when
  verification risk is meaningful.
- For architecture/API/database/integration work: Architect + Code Investigator
  + Reviewer.
- For UI/product work: Product / UX Reviewer + QA Engineer + Reviewer.
- For security/compliance work: Security Engineer + Reviewer + QA Engineer.
- For production/release/deploy work: DevOps / Release Engineer + Security
  Engineer + QA Engineer.
- For trading/EA/quant/backtest work: Quant / Backtest Reviewer + Reviewer +
  QA Engineer.

Before spawning any specialist or assigning any file edits, create a
coordination packet:

- `goal`: exact objective
- `riskClass`: array of every matched risk class
- `mode`: `smart-subagents`
- `rolesUsed`: exact roles and reasons
- `rolesNotUsed`: skipped roles and reasons
- `readWritePermissions`
- `fileOwnershipMap`
- actual `capabilityPlan` and exact per-role `capabilityIds`
- `evidenceContract`
- `conflictRule`
- `stopConditions`
- `verificationGate`
- `handoffGate`

Use `jstack_team_plan` with `team_mode="smart-subagents"` and
`jstack_dispatch_check` with `team_mode="smart-subagents"` and
the actual `coordination_packet` object when available. Also use
`jstack_plan(team_mode="smart-subagents", learning_mode=resolved_learning_mode)`.
Specialists are read-only by default. The Lead may implement. If an editing
specialist is used, only a Builder may edit implementation, and only inside an
explicitly assigned disjoint write scope.

Dispatch only the capability subset routed to each existing role. Capabilities
add method, required evidence, stop conditions, audit domains, and loop
controls; they never grant tools, writes, delegation, approvals, or release
authority. Each role, including Lead, returns `jstack.specialist.result.v1`
plus metadata-only `jstack.specialist.telemetry.v1`. The Lead calls
`jstack_specialist_result` for every exact assignment, then
`jstack_specialist_handoff_check` before completion. Do not store raw prompts,
messages, tool arguments, command/model output, source contents, or secrets.
Missing, stale, partial, permission-unsafe, capability-drifted, or contradictory
receipt sets block handoff until explicitly reconciled with evidence.

The MCP plans and validates the team; it does not spawn one. Use platform
multi-agent tools for actual dispatch, collection, and closure. Finish in the
order outcome, evidence, residual risk, then an optional three-line mastery
capsule.

If more than three specialists are materially required, stop and recommend
`/jstack-full-team` instead of silently widening smart mode.

If multi-agent tools are unavailable, write `No subagents deployed:` and give
the concrete reason. Retain `team_mode="smart-subagents"` in planning and
apply its evidence rubric, while one Lead performs the actual work.

For an active multi-agent JStack loop, pass the current validated
`specialist_handoff_receipt` to every checkpoint and finalization.

For production/release work, the Lead declares `core` plus every applicable
surface on the clean integrated candidate. Route selected launch-control
evidence through existing Security, QA, DevOps, Product, Reviewer, and
accountable human owners; only the Lead registers and finalizes it. Missing or
failed blocker/required evidence blocks handoff. Public-web, commercial,
payment, and regulated-data profiles also require a release-profile audit by
default. This adds capability packs, not a sixth command or new role.

Default to local-only. Team deployment authorizes staffing only. Repository
creation, remote add/change, commit, push, pull-request creation, merge, tag,
release, deployment, and production mutation each require their own exact
signed one-time JStack external-action permit. Only the accountable Lead may
run challenge -> human signature outside Codex -> authorize -> fresh provider
observation -> consume and then execute the exact action once before expiry.
No subagent may request, sign, consume, or exercise that authority. Broad task
verbs, phase/remediation approval, readiness, or specialist handoff never
substitute, and no shell/provider path may bypass the boundary.
