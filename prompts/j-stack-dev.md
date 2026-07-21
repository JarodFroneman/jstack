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
3. Call `jstack_runtime_status` first. A successful call proves the MCP is
   mounted. Use `jstack_detect_project`, then branch on `evidenceMode`.
4. For `git`, use `jstack_policy_check`,
   `jstack_plan(team_mode="single-lead", learning_mode=resolved_learning_mode)`,
   apply the returned Lead `capabilityIds`, and use `jstack_preflight` when
   applicable. Capability packs specialize the Lead but never authorize
   subagents or expand permissions.
5. For `artifact-only`, state
   `MCP mounted; project binding is artifact-only.`, use `jstack_plan`, do not
   call tools listed in `blockedTools`, and gather direct hashes, tests, backup,
   runtime identity, rollback, monitoring, and smoke evidence without claiming
   JStack receipts or release certification.
6. Implement the smallest coherent change.
7. Run focused review, security, QA, release, or quant checks required by the
   risk class. In `git` mode, QA execution must use the exact reviewed
   revision/fingerprint and return evidence receipts. In `artifact-only` mode,
   preserve direct evidence and its limitation instead.
8. In Git mode, submit the Lead's exact `jstack.specialist.result.v1` and
   metadata-only `jstack.specialist.telemetry.v1` through
   `jstack_specialist_result`, then validate the one-role set with
   `jstack_specialist_handoff_check`. Never store raw prompts, messages, tool
   arguments, command/model output, source contents, or secrets. A failed,
   partial, stale, or capability-incomplete receipt blocks completion.
9. Report outcome, evidence, residual risk, then an optional three-line mastery
   capsule.

If the task grows beyond a single Lead Engineer, stop and recommend
`/jstack-subagents` or `/jstack-full-team` rather than silently escalating.

Use the installed `jstack-dev` skill and normal Codex fallback only when
`jstack_runtime_status` itself is unavailable or unreachable. Never relabel a
Git requirement, invalid input, policy denial, or failed gate as an MCP
attachment failure. Upstream gstack is optional.
