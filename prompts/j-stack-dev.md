---
description: Run JStack enterprise workflow in single-lead mode
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `single-lead`.

This command is intentionally the non-subagent version. Never spawn subagents
under this command. If the user also asks for subagents, stop and direct them to
`/jstack-subagents` or `/jstack-full-team`.

Use one Lead Engineer to run the enterprise gates:

Resolve learning mode first: use an explicit user request for `off`, `coach`,
or `assessment`; otherwise use `embedded`. Pass that resolved value to every
planning call.

1. Classify risk.
2. Read project instructions and restore context.
3. Use `jstack_detect_project`, `jstack_policy_check`,
   `jstack_plan(team_mode="single-lead", learning_mode=resolved_learning_mode)`, and
   `jstack_preflight` when available.
4. Implement the smallest coherent change.
5. Run focused review, security, QA, release, or quant checks required by the
   risk class. QA execution must use the exact reviewed revision/fingerprint
   and return evidence receipts.
6. Report outcome, evidence, residual risk, then an optional three-line mastery
   capsule.

If the task grows beyond a single Lead Engineer, stop and recommend
`/jstack-subagents` or `/jstack-full-team` rather than silently escalating.

If the `jstack_*` MCP tools are unavailable, use the installed `jstack-dev`
skill and normal Codex tools. Upstream gstack is optional.
