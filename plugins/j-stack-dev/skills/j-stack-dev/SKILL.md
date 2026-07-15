---
name: j-stack-dev
description: Single Lead Engineer JStack workflow. Use when the user invokes /j-stack-dev or asks for the standard JStack development workflow without subagents.
metadata:
  short-description: Run JStack as a single Lead Engineer
---

# JStack Dev

Use the JStack Think -> Plan -> Build -> Review -> Test -> Ship structure.

Default behavior:

1. Operate as the Lead Engineer.
2. Do not deploy subagents. Command mode is authoritative.
3. Call `jstack_runtime_status` first. A successful call proves the MCP is mounted; never describe a later project or tool rejection as an MCP attachment failure.
4. Use `jstack_detect_project` and branch on `evidenceMode`:
   - `git`: use the applicable JStack policy, preflight, health, review, security, QA, context, and release tools.
   - `artifact-only`: state `MCP mounted; project binding is artifact-only.`, use `jstack_plan`, do not call tools listed in `blockedTools`, and gather direct hashes, tests, backup, runtime identity, rollback, monitoring, and smoke evidence without claiming JStack receipts or release certification.
5. Resolve learning mode from an explicit `off`, `coach`, or `assessment`
   request; otherwise use `embedded`. Call `jstack_plan` with
   `team_mode="single-lead"` and that resolved mode.
6. Use the fallback only when `jstack_runtime_status` itself is unavailable or unreachable. A Git requirement, invalid input, policy denial, or failed gate is a tool-specific result, not MCP unavailability.
7. Respect project `AGENTS.md`, safety rules, branch/deploy rules, and explicit user approvals.
8. When an active JStack loop supplies a `loopId`, execute only the current
   single-lead iteration. Let `jstack_loop_checkpoint` and
   `jstack_loop_finalize` own convergence and terminal status.

If the task grows beyond a single Lead Engineer, stop and recommend
`/jstack-subagents` or `/jstack-full-team` rather than silently escalating.

This command is for substantial development work. Tiny one-line fixes may use normal Codex workflow.
