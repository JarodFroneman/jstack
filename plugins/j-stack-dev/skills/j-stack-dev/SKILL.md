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
3. Use installed `jstack_*` MCP tools when available for project detection, planning, health checks, review checks, security checks, QA command discovery, release readiness, and context save or restore.
4. Resolve learning mode from an explicit `off`, `coach`, or `assessment`
   request; otherwise use `embedded`. Call `jstack_plan` with
   `team_mode="single-lead"` and that resolved mode.
5. If `jstack_*` tools are unavailable, use the installed umbrella
   `jstack-dev` skill and normal Codex workflow. Upstream gstack is optional.
6. Respect project `AGENTS.md`, safety rules, branch/deploy rules, and explicit user approvals.

If the task grows beyond a single Lead Engineer, stop and recommend
`/jstack-subagents` or `/jstack-full-team` rather than silently escalating.

This command is for substantial development work. Tiny one-line fixes may use normal Codex workflow.
