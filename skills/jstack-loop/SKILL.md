---
name: jstack-loop
description: Run bounded JStack goal loops or durable multi-phase programs until current acceptance evidence succeeds or an auditable stop or wait state is reached. Use when the user invokes /jstack-loop, asks JStack to keep working toward a goal, requests a long-running or monolithic project with human checkpoints, or combines loop engineering with single-lead, specialist-team, or full-team JStack delivery.
---

# JStack Loop Engineer

Use Codex Goal mode for continuation and JStack for contracts, state, evidence,
gates, circuit breakers, and terminal decisions. JStack is not an autonomous
agent runtime. "Until done" never removes limits, approvals, or release gates.

## Select The Orchestration Level

Call `jstack_runtime_status`, `jstack_detect_project`, and `jstack_plan` before
creating state. Execution requires `evidenceMode="git"`; report the exact Git
binding limitation for `artifact-only` projects.

Choose from project evidence, not a preset phase count:

- Use one bounded loop for one coherent goal with one acceptance boundary.
- Use a program when the outcome has independently verifiable phases, a
  dependency graph, different execution modes or scopes, long human/external
  waits, or program-level integration evidence.
- Never hardcode a phase count or any domain-specific roadmap. The program accepts
  a project-derived DAG from one phase up to its policy ceiling.
- Do not split work merely to create activity. Every phase needs a distinct
  outcome, acceptance contract, scope, dependency reason, and optional output.

Read [protocol.md](references/protocol.md) for bounded loops. Read
[program-protocol.md](references/program-protocol.md) before operating a
program. Read [human-gates.md](references/human-gates.md) for approvals and
[evidence-registry.md](references/evidence-registry.md) for external evidence.

## Fix Execution Authority

Resolve staffing only from explicit user intent:

- `single-lead` is the default and deploys no subagents.
- `smart-subagents` requires an explicit JStack Subagents request.
- `full-team` requires an explicit JStack Full Team request.
- JStack Audit stays independent and read-only.

A program may mix execution modes only when the exact phase assignments are
shown and explicitly confirmed in program readiness. Task size alone never
authorizes staffing escalation. Each child loop applies the corresponding
JStack Dev, Subagents, or Full Team workflow without changing its phase goal.

Use `L0` for design, `L1` for read/evaluate, `L2` for supervised writes, and
`L3` only for explicitly approved low-risk work in an isolated linked
worktree. Default implementation work to `L2`.

## Run One Bounded Loop

1. Build source-attributed `goal_context`: stakeholders, current and desired
   states, constraints, non-goals, assumptions, sources, niche requirements,
   open questions, and material inference.
2. Define observable QA, security, audit, review, artifact, or named human
   acceptance criteria. Bound paths, blocked actions, iterations, active time,
   failures, and changed files. Never supply arbitrary shell commands.
3. Call `jstack_loop_goal_readiness`. Resolve `needs_context` from inspected
   evidence first, asking only returned blocking questions. For
   `needs_confirmation`, show the preview and exact digest and wait for real
   confirmation. Never fabricate a confirmation reference.
   Pass any explicitly requested `capability_ids` on every readiness, start,
   and material revision call. The returned preview binds catalog, selection,
   exact team-role assignments, audit domains, loop controls, and the
   no-permission-expansion invariant into the readiness digest.
4. Pass the returned receipt unchanged to `jstack_loop_start`, including the
   same `capability_ids`. Create or reuse
   the matching native Goal only after JStack state exists.
5. On every resumed turn call `jstack_loop_status`, then run one meaningful
   Think -> Plan -> Build -> Review -> Test cycle in the fixed execution mode.
6. Call `jstack_loop_checkpoint` with current receipts and factual progress.
   `smart-subagents` and `full-team` loops must first validate all current role
   results with `jstack_specialist_handoff_check` and pass its
   `specialist_handoff_receipt`; missing, stale, incomplete, capability-drifted,
   or unreconciled specialist evidence blocks the checkpoint.
   Follow `continue`, `ready_to_finalize`, `needs_approval`, or `policy_stop`.
7. A `needs_approval` state releases the write lease and pauses active time.
   Resume through an explicit approved revision; do not mark the native Goal
   blocked merely because a person or external system must respond.
8. Material goal, context, mode, capability selection, autonomy, risk,
   criterion, scope, or limit changes require fresh readiness and
   `jstack_loop_revise`.
9. Call `jstack_loop_finalize` only with current evidence for the original
   baseline, including the current specialist handoff receipt for multi-agent
   modes. Complete the native Goal only after a passed completion receipt.
   On user stop, call `jstack_loop_stop` and preserve the durable record.

## Establish A Program Contract

1. Inspect the project roadmap, architecture, risks, release boundary, and
   available evidence. Derive phases and dependencies from real deliverables.
2. Give every phase a stable ID, title, exact goal, dependencies, approved
   execution mode, autonomy, risk, allowed paths, acceptance criteria, gates,
   declared outputs, and parallel/worktree flags.
3. Use a DAG, not an assumed linear list. A dependency means downstream
   acceptance is invalid without that upstream proof.
4. Define human gates for accountable decisions and external gates for
   backtests, certifications, data exports, device results, legal sign-off
   artifacts, or other non-Codex evidence. Waiting is a durable pause.
5. Define program-level final acceptance. Enterprise policy requires current
   release-audit, security, and deterministic integrated-review evidence.
6. Set ceilings for phase count, parallel phases, and active minutes. These
   are safety limits, not a target plan size. Preserve blocked release and
   production actions.
7. Call `jstack_program_goal_readiness`. Resolve at most three returned
   questions per round. Show the exact DAG preview and readiness digest, then
   wait for the user's factual confirmation.
8. Generate one stable unique `operation_id` for the start call and reuse it
   only when retrying that exact payload. Pass the readiness receipt unchanged
   to `jstack_program_start`.
9. Create or reuse the matching native Goal using the complete program outcome.
   Do not create one native Goal per phase unless the user explicitly requests
   separately owned tasks.

## Execute Program Phases

1. On every turn call `jstack_program_status`; omit no known program ID. Stop
   mutations if integrity reports policy, tool, baseline, output, or child-proof
   drift. Use an approved program revision to restore a changed contract.
2. Call `jstack_program_next`. It may schedule several phases only when the
   contract marks them parallel-safe, each uses a linked worktree, their
   top-level scopes are disjoint, and policy capacity remains.
3. For each scheduled phase, create a bounded child loop whose goal, mode,
   autonomy, risk, paths, and acceptance criteria exactly match the phase.
   Carry every program- and phase-level blocked action into that child; loop
   defaults may strengthen the list but never remove a prohibition. Route and
   bind phase-specific capabilities during child goal readiness; do not reuse a
   capability selection from a different phase goal. Complete child readiness
   and start normally.
4. Bind the active child with `jstack_program_phase_bind`, using a fresh stable
   `operation_id`. Execute it under its approved JStack delivery workflow.
5. Finalize the child loop with current evidence. Pass its completion receipt
   to `jstack_program_phase_complete` using another unique operation ID. JStack
   revalidates durable loop state and hashes every declared output.
6. Never advance a phase from a summary, subagent claim, human statement, or
   caller-supplied boolean. Only current child proof plus required gates moves
   the DAG.
7. If a before/after/final human gate is pending, call
   `jstack_program_gate_challenge`. A configured human runs the external signer
   and returns the signed attestation; Codex must not sign it. Resolve it with a
   unique `operation_id`.
8. For an external gate, place a bounded artifact inside the project or
   `~/.jstack/evidence`, then call `jstack_program_evidence_register`. JStack
   records its hash, provenance reference, and expiry. Replacement invalidates
   affected downstream proof.
9. Use `jstack_program_pause` only after active child loops reach checkpoints.
   Human and external wait states already pause the program active-time clock.
   Resume only after integrity revalidation and an explicit reference.
10. Any phase, dependency, gate, scope, mode, or final-acceptance change needs
    exact-digest readiness and `jstack_program_revise`. Changed phases and all
    transitive dependants are invalidated; unaffected current phase proof is
    kept. Every gate record is cleared because its signature or evidence was
    bound to the prior program digest, so collect it again when required.

## Complete Or Cancel A Program

Call `jstack_program_finalize` only when every phase and final gate is current.
Provide fresh final QA receipts where contracted, a current security receipt,
a release-profile audit receipt, deterministic integrated review, declared
artifacts, and a factual completion summary. Use a new stable `operation_id`.

Complete the native Goal only after finalization returns a passed current
program completion receipt. That receipt never authorizes commit, push, merge,
deployment, production mutation, or release.

Before cancelling, stop or finalize every active child loop. Call
`jstack_program_cancel` with a reason and operation ID; preserve the auditable
state. Human waiting, external waiting, uncertainty, or budget pressure is not
success. Apply the platform's three-consecutive-turn rule only to native Goal
blocked status, not to JStack wait states.

For deliberate practice, use the `loop` mastery track and read
[mastery-system.md](references/mastery-system.md).
