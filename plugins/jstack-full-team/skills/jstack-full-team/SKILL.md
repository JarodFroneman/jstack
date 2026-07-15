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
- `evidenceContract`, `conflictRule`, and `stopConditions`
- `verificationGate` and `handoffGate`

Full-team wave pattern:

1. Discovery: Architect, Code Investigator, Product/UX, and Quant.
2. Build: Builder only after Lead approval of scope.
3. Review: Reviewer, QA, Security, DevOps, Documentation.
4. Synthesis: Lead reconciles evidence, resolves conflicts, verifies, and hands off.

If multi-agent tools are unavailable, state `No subagents deployed:` with the
concrete reason. Retain `team_mode="full-team"` in planning and apply its
evidence rubric while one Lead performs the work.

When an active JStack loop supplies a `loopId`, keep `team_mode="full-team"`
fixed for that contract and execute only the current wave-bounded iteration.
The loop checkpoint owns convergence and terminal status.
