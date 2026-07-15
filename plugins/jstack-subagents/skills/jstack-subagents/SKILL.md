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
- `evidenceContract`, `conflictRule`, and `stopConditions`
- `verificationGate` and `handoffGate`

Pass the actual packet object to `jstack_dispatch_check`; a boolean packet
claim is invalid. Use `jstack_plan` with
`team_mode="smart-subagents"` and the resolved learning mode: explicit
`off`, `coach`, or `assessment`, otherwise `embedded`.
The MCP plans and validates; platform multi-agent tools perform actual
dispatch, collection, and closure.

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
current iteration. The loop checkpoint owns convergence and terminal status.

No two editing agents may own the same file or module. If scope cannot be split
cleanly, use one Builder. The Lead Engineer resolves conflicts using evidence,
reproduction, project rules, and safety gates.

If multi-agent tools are unavailable, state `No subagents deployed:` with the
concrete reason. Retain `team_mode="smart-subagents"` in planning and apply
its evidence rubric while one Lead performs the work.
