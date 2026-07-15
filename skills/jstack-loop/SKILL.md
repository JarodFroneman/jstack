---
name: jstack-loop
description: Run bounded, durable JStack goal loops that keep Codex working through verified iterations until an acceptance contract succeeds or an auditable stop condition is reached. Use when the user invokes /jstack-loop, asks JStack to loop until a goal is completed, requests persistent goal engineering across Codex turns, or explicitly combines loop engineering with single-lead, specialist-team, or full-team JStack delivery.
---

# JStack Loop Engineer

Use Codex Goal mode for continuation and JStack for the contract, state,
evidence, circuit breakers, and completion decision. Never describe the MCP as
an autonomous agent runtime and never interpret "until done" as unbounded work.

## Establish The Contract

1. Call `jstack_runtime_status` first. A successful response proves the MCP is
   mounted. Call `jstack_detect_project`; loop execution requires
   `evidenceMode="git"`. For `artifact-only`, stop with the exact binding
   limitation instead of claiming an MCP attachment failure.
2. Read project instructions, inspect current Git state, classify risk, and call
   `jstack_plan` with the fixed execution mode.
3. Resolve execution mode only from explicit user intent:
   - Use `single-lead` by default and deploy no subagents.
   - Use `smart-subagents` only when the user explicitly combines the loop with
     JStack Subagents.
   - Use `full-team` only when the user explicitly combines the loop with
     JStack Full Team.
   - Keep JStack Audit independent and read-only. Use it as an acceptance gate,
     never as an editing mode.
4. Select bounded autonomy: `L0` design only, `L1` read/evaluate, `L2`
   supervised implementation, or `L3` explicitly approved low-risk work in an
   isolated Git worktree. Default implementation work to `L2`; never infer
   `L3` from phrases such as "keep going."
5. Build `goal_context` from repository evidence and the user's words. Record
   the domain and stakeholders, current and desired states, constraints,
   non-goals, authoritative context sources, niche-specific requirements,
   assumptions, unresolved questions, and every material field Codex inferred.
   Never silently invent an approval, requirement, or definition of success.
6. Define observable acceptance criteria using JStack QA command keys,
   security receipts, audit receipts, deterministic review, exact artifacts,
   or named human approval references. Define non-goals, allowed paths, blocked
   actions, and iteration/time/change limits. Do not pass arbitrary shell
   commands into the loop contract.
7. Call `jstack_loop_goal_readiness` with the complete candidate contract:
   - For `needs_context`, resolve facts from inspected sources first, then ask
     only the returned blocking questions. The tool returns at most three at a
     time; preserve its full `gaps` list across rounds.
   - For `needs_confirmation`, show the contract preview, reasons, and exact
     readiness digest. Ask the user to confirm that contract. Only after a real
     confirmation may you resubmit `confirmed_readiness_digest` with a factual
     `confirmation_reference`; never fabricate the reference.
   - For `ready`, pass the returned session-local
     `goal_readiness_receipt` unchanged to `jstack_loop_start`. Reassess if the
     repository or any semantic contract field changes before start.
8. Pass `token_budget` only when the user explicitly supplied a positive
   numeric budget.
9. If native Goal tools are available, call `get_goal` before creating JStack
   state. Reuse an unfinished goal only when it represents the same objective;
   for a different unfinished goal, do not start a loop and ask the user to
   finish or cancel that goal first.
10. Call `jstack_loop_start` only with the assessed `goal_context` and current
    readiness receipt. Use the returned `loopId`, baseline commit, and contract
    digest for all later work.

Read [protocol.md](references/protocol.md) when designing criteria, autonomy,
or a composed team loop.

## Start Native Goal Mode

After a successful loop start, call `create_goal` with the exact contracted
objective when no matching unfinished goal already exists. Set its token budget
only when the user explicitly supplied one.
If Goal tools are unavailable, do not claim cross-turn persistence; perform
only a bounded current-turn cycle and finalize or stop the JStack loop before
ending the turn. If native Goal creation fails after loop start, call
`jstack_loop_stop` so the write lease is not orphaned.

## Iterate

1. On every resumed turn, call `jstack_loop_status` before changing files.
   Omit `loop_id` to recover the repository's active or latest loop when task
   context no longer contains the ID.
2. Run Think -> Plan -> Build -> Review -> Test using the fixed execution mode.
   Apply the corresponding JStack Dev, Subagents, or Full Team rules without
   silently changing staffing.
3. After one meaningful build-and-verify cycle, call
   `jstack_loop_checkpoint`. Supply only current JStack receipts and a concise
   factual summary. Use a stable failure signature for the same failure and
   report a concrete blocker when one exists.
4. Follow the returned decision:
   - `continue`: perform the next smallest evidence-producing iteration.
   - `ready_to_finalize`: gather final current evidence and finalize.
   - `needs_approval`: stop mutations and request the specific decision. Revise
     the contract only with an explicit approval reference.
   - `policy_stop`: stop. Do not bypass the scope, protected-path, or policy
     failure.
5. Treat iteration, elapsed-time, repeated-failure, no-progress, and
   oscillation breakers as real stops. Do not reset them by cosmetic edits.
6. Before changing the goal, criteria, delivery mode, autonomy, risk, paths,
   blocked actions, limits, token budget, or goal context, submit the complete
   revised candidate and `loop_id` to `jstack_loop_goal_readiness`. Pass its
   fresh receipt to `jstack_loop_revise`. A human-approval update or explicit
   retry/resume reference that leaves those fields unchanged carries the prior
   readiness decision.

## Complete Or Stop

Call `jstack_loop_finalize` only after every criterion has current evidence.
Use the baseline commit from `jstack_loop_status` for QA, security, and audit
evidence so the full loop delta is covered.

Call `update_goal(status="complete")` only after finalization returns a passed
`completionReceipt` for the current project fingerprint. A completion receipt
does not authorize commit, push, deployment, or release.

Call `update_goal(status="blocked")` only after the same blocker has recurred
for three consecutive Codex Goal turns. MCP checkpoint counts are advisory and
do not substitute for that platform rule. Budget exhaustion, uncertainty, or a
single approval wait is not completion and is not automatically blocked.

When the user stops the work, call `jstack_loop_stop`, release the write lease,
and report the durable state. Never mark a stopped loop complete.

For deliberate practice, use the `loop` mastery track. Read
[mastery-system.md](references/mastery-system.md) only when the user requests
training, assessment, or mastery progression.
