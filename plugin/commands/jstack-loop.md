---
description: Run a bounded JStack loop until verified completion or an auditable stop
argument-hint: [GOAL]
---

Apply the JStack Loop Engineer workflow to this goal:

$ARGUMENTS

Default to `execution_mode="single-lead"`. Use `L2` for supervised
implementation, `L0`/`L1` for non-writing goals, and never infer `L3`. Do not
deploy subagents unless the user explicitly combines this invocation with
JStack Subagents or JStack Full Team.

Use the installed `jstack-loop` skill. Call `jstack_runtime_status` first,
require a Git-backed project, design an observable bounded contract, call
`get_goal` to reject a conflicting unfinished goal, call `jstack_loop_start`,
and then create or reuse the matching native Codex goal. Iterate through the
selected JStack delivery workflow and call `jstack_loop_checkpoint` after each
meaningful build-and-verify cycle.

Continue only while the tool returns `continue`. Honor approval and policy
stops. Finalize only when every contracted QA, security, audit, review,
artifact, or human criterion has current evidence, then mark the native goal
complete only when `jstack_loop_finalize` returns a passed completion receipt.

Never describe a Git rejection as an MCP attachment failure. Never treat
"until done" as permission to bypass path, security, release, deployment,
budget, or user-approval boundaries.
