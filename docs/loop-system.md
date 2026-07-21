# JStack Loop Engineer

`/jstack-loop` selects the smallest honest orchestration level: one bounded,
evidence-producing loop for one acceptance boundary, or a project-derived
Program -> Phase DAG for independently verified phases and intervention waits.
There is no built-in phase count or domain roadmap.

See [the program system](program-system.md) when the goal needs dependencies,
phase-specific JStack teams, human/external gates, or final integration proof.

## Composition

The loop does not replace the existing commands:

- `/j-stack-dev` remains the default single Lead Engineer execution mode.
- `/jstack-subagents` can execute loop iterations when explicitly selected.
- `/jstack-full-team` can execute loop iterations when explicitly selected.
- `/jstack-audit` remains read-only and can provide an acceptance receipt.

The execution mode is fixed in the contract. Widening the team requires an
approved contract revision.

For a program, execution mode is fixed per phase in the exact confirmed DAG.
Mixed modes require explicit confirmation; project size never authorizes an
implicit escalation.

## Lifecycle

1. Inspect the Git project, policy, risk, and available QA commands.
2. Build domain-aware goal context covering stakeholders, current and desired
   states, constraints, non-goals, sources, niche requirements, assumptions,
   and unresolved or inferred fields.
3. Define acceptance criteria, allowed paths, blocked actions, autonomy, and
   convergence limits, then route the task's capability plan.
4. Run the Goal Readiness Gate, resolve its targeted context questions, and
   obtain exact-digest confirmation when required.
5. Start durable JStack loop state with the readiness receipt and create the
   native Codex goal.
6. Run one Think -> Plan -> Build -> Review -> Test cycle.
7. Checkpoint current receipts and derived Git/artifact evidence.
8. Continue, request approval, stop on policy, or gather final evidence.
9. Finalize and mark the native goal complete only with a current completion
   receipt.

## Goal Readiness

`jstack_loop_goal_readiness` accepts a partial or complete candidate contract.
It reports every missing field but asks at most three targeted questions per
round. Codex should answer from inspected repository/runtime evidence first and
ask the user only for unresolved intent, authority, or domain facts.

Complete context is tailored to the task's niche. Financial/data goals require
authoritative sources, calculation definitions, horizons, and tolerances;
security goals require assets, trust boundaries, threats, and obligations;
production goals require environment, rollout, rollback, monitoring, and human
authority. Equivalent requirements apply to product, research, and unknown
domains.

Ambiguity, inference, assumptions, non-blocking unknowns, sensitive domains,
medium-or-higher risk, and L3 trigger a confirmation round. The user confirms
the exact returned preview and digest. The resulting receipt is session-local
and bound to the semantic contract plus current Git and policy state.

Changing a semantic contract field requires a fresh readiness receipt bound to
the loop ID and prior contract digest. Approval-only and explicit retry/resume
revisions carry existing readiness when the contracted target is unchanged.

Readiness, start, durable status, material revisions, and completion all bind a
`capabilityContract`: catalog/selection/goal digests, execution mode, exact
role assignments, explicit capability IDs, strengthened audit domains, loop
controls, and the no-permission-expansion invariant. Changing explicit IDs is a
material revision requiring fresh readiness.

For `smart-subagents` and `full-team`, each checkpoint and finalization must
include a current `specialist_handoff_receipt` matching the capability contract
and Git state. Single-lead loops validate the Lead's structured result in the
workflow but do not require a multi-agent handoff at every checkpoint.

## Autonomy

- `L0`: design only.
- `L1`: read and evaluate.
- `L2`: supervised implementation and the default for writing tasks.
- `L3`: explicitly approved low-risk automation in a linked Git worktree.

Write loops require a clean starting state and one exclusive repository lease.
L3 additionally requires bounded paths and current QA, security, audit, and
review evidence.

The lease is scoped to one Git checkout; separate linked worktrees remain
isolated execution surfaces. Scope globs are segment-aware: `src/*` is one
level, while `src/**` is recursive. L3 scopes must start with a literal
top-level entry.

The baseline commit must remain the exact merge base of `HEAD`. Rebase, reset,
or branch drift cannot silently change the evidence range. Hidden Git index
flags, unrepresentable path identities, snapshot or contract tampering, and
out-of-scope changes fail closed.

## Terminal Outcomes

- `succeeded`: every criterion passed against the current project fingerprint.
- `needs_approval`: a blocker or convergence breaker requires judgment.
- `stopped`: user stop or fail-closed policy/scope violation.

A paused loop rejects further checkpoints and finalization until an explicit
contract or resume approval revision is recorded. Policy or JStack protocol
version drift uses this approval path; a true scope or protected-policy
violation is terminal.

Iteration counts do not determine Codex Goal blocked status. Goal mode may mark
blocked only after the same blocker persists for three consecutive Goal turns.

An approval wait now pauses active elapsed time and releases a write-capable
loop's checkout lease. An approved resume revision must reacquire it; this can
fail when another child loop currently owns that checkout.

See [ADR 0002](adr/0002-jstack-loop-protocol.md) for protocol invariants and
[ADR 0003](adr/0003-goal-readiness-gate.md) for the intake decision. See
[ADR 0004](adr/0004-program-orchestration-protocol.md) for multi-phase
orchestration and [loop mastery](loop-mastery-system.md) for the training path.
