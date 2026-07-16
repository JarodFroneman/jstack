---
description: Run a verified bounded loop or multi-phase JStack program
argument-hint: [GOAL]
---

Apply the JStack Loop Engineer workflow to this goal:

$ARGUMENTS

Call `jstack_runtime_status` first, require a Git-backed project, and inspect
the actual goal before selecting one bounded loop or a multi-phase program.
Derive phase count and dependencies from independently verifiable project
outcomes. Never assume a fixed phase count or any domain-specific roadmap.

Default phase execution to `single-lead` and supervised writes to `L2`. Use
JStack Subagents or JStack Full Team only when the user explicitly authorizes
that mode; never infer staffing or L3 autonomy from project size.

For a bounded goal, follow `jstack_loop_goal_readiness`, start, status,
checkpoint, revision, and finalization with current evidence. For a program,
build an exact Program -> Phase DAG, call `jstack_program_goal_readiness`, wait
for confirmation, and start with a unique stable `operation_id`. Schedule each
phase through an exact bounded child loop, bind and complete it with current
receipts, and revalidate declared outputs.

Treat human and external gates as durable wait states that suspend active time.
Codex must not sign human approval challenges. Use fresh operation IDs for
state changes and reuse an ID only to retry the exact same payload.

Create or reuse the matching native Codex Goal only after JStack state exists.
Complete it only after a passed current loop or program completion receipt.
Never describe a Git rejection as an MCP attachment failure, and never treat
"until done" as authority to bypass scope, security, release, deployment,
budget, or human-approval boundaries.
