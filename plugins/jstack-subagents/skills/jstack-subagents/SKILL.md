---
name: jstack-subagents
description: JStack specialist-team workflow. Use when the user invokes /jstack-subagents or explicitly asks to deploy the right subagent team, normally two or three specialists.
metadata:
  short-description: Deploy the right JStack specialist team
---

# JStack Subagents

Treat this command as explicit user approval to deploy subagents when multi-agent tools are available.

Default behavior:

1. Keep the Lead Engineer accountable for scope, synthesis, implementation decisions, verification, and handoff.
2. Deploy the right specialist team for the task, normally two or three specialists.
3. Use Code Investigator plus Reviewer for normal feature or bug work.
4. Add QA Engineer when verification risk is meaningful.
5. Use Architect for architecture, API, database, or integration-sensitive work.
6. Use Product / UX Reviewer for UI and product work.
7. Use Security Engineer for security or compliance work.
8. Use DevOps / Release Engineer for production, deploy, and release work.
9. Use Quant / Backtest Reviewer for trading, EA, quant, or backtest work.
10. Specialists are read-only by default. Only assign edits to a Builder with a disjoint write scope.

Before dispatch, require a coordination packet:

- `goal`
- `riskClass` array
- `mode: smart-subagents`
- `rolesUsed` and `rolesNotUsed`
- `readWritePermissions` and `fileOwnershipMap`
- actual `capabilityPlan` and exact per-role `capabilityIds`
- `evidenceContract`, `conflictRule`, and `stopConditions`
- `verificationGate` and `handoffGate`

Pass the actual packet object to `jstack_dispatch_check`; a boolean packet
claim is invalid. Use `jstack_plan` with
`team_mode="smart-subagents"` and the resolved learning mode: explicit
`off`, `coach`, or `assessment`, otherwise `embedded`.
The MCP plans and validates; platform multi-agent tools perform actual
dispatch, collection, and closure.

Dispatch each specialist with only the capability subset returned for its core
role. Capability packs add methods, evidence requirements, stop conditions,
audit domains, and loop controls; they never grant tools, writes, delegation,
approvals, or release authority. Each routed role, including the Lead, returns
a `jstack.specialist.result.v1` object and metadata-only
`jstack.specialist.telemetry.v1`. The Lead calls `jstack_specialist_result` for
each exact role/capability assignment and calls
`jstack_specialist_handoff_check` before completion. Raw prompts, messages,
tool arguments, command/model output, source contents, and secrets are
forbidden in telemetry. Missing, stale, partial, conflicting, permission-unsafe,
or capability-drifted receipts block handoff; contradictions need an explicit
evidence-backed Lead resolution.

Call `jstack_runtime_status` before project tools. A successful call proves the
MCP is mounted. Use `jstack_detect_project` and branch on `evidenceMode`. For
`artifact-only`, state `MCP mounted; project binding is artifact-only.`, keep
team planning and dispatch validation, do not call tools listed in
`blockedTools`, and gather direct artifact evidence without claiming JStack
receipts or release certification. Only use the MCP fallback when
`jstack_runtime_status` itself is unavailable or unreachable; never relabel a
Git requirement or failed gate as an MCP attachment failure.

The Lead may implement. If a specialist edits implementation, it must be the
Builder with an explicit disjoint scope. If more than three specialists are
required, stop and recommend `/jstack-full-team`.

When an active JStack loop supplies a `loopId`, keep
`team_mode="smart-subagents"` fixed for that contract and execute only the
current iteration. Pass the current validated `specialist_handoff_receipt` to
every checkpoint and finalization; the loop owns convergence and terminal
status.

No two editing agents may own the same file or module. If scope cannot be split
cleanly, use one Builder. The Lead Engineer resolves conflicts using evidence,
reproduction, project rules, and safety gates.

For production/release work, the Lead declares `core` plus every applicable
product surface with `jstack_launch_assess` on the clean integrated candidate.
Assign evidence collection to existing roles: Security owns security controls,
QA owns interaction/device/delivery checks, DevOps owns transport and
observability, Product owns findability/analytics semantics, and accountable
humans own legal and business facts. Specialists return bounded artifacts and
attestations; only the Lead registers and finalizes the exact selection.
Missing or failed blocker/required launch evidence blocks handoff. Public-web,
commercial, payment, and regulated-data profiles also require the current
release-profile audit receipt by default. This is a capability of the existing
team, not a new role or staffing command.

If multi-agent tools are unavailable, state `No subagents deployed:` with the
concrete reason. Retain `team_mode="smart-subagents"` in planning and apply
its evidence rubric while one Lead performs the work.

Default to local-only. Team approval authorizes staffing only. Repository
creation, remote add/change, commit, push, pull-request creation, merge, tag,
release, deployment, and production mutation each require a separate exact
signed one-time JStack external-action permit. Only the Lead may perform
challenge -> the human runs the returned approval command outside Codex and
types `APPROVE ONCE` -> authorize by ID -> fresh provider
observation -> consume, followed by one exact operation before expiry. No
specialist may request, sign, consume, or exercise this authority, and no broad
verb, phase/remediation approval, readiness, handoff, pasted token, shell, or
provider path may substitute for or bypass it.
