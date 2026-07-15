# JStack Loop Engineer

`/jstack-loop` keeps a JStack task moving through bounded, evidence-producing
iterations until the contracted goal succeeds or a real stop condition is
reached.

## Composition

The loop does not replace the existing commands:

- `/j-stack-dev` remains the default single Lead Engineer execution mode.
- `/jstack-subagents` can execute loop iterations when explicitly selected.
- `/jstack-full-team` can execute loop iterations when explicitly selected.
- `/jstack-audit` remains read-only and can provide an acceptance receipt.

The execution mode is fixed in the contract. Widening the team requires an
approved contract revision.

## Lifecycle

1. Inspect the Git project, policy, risk, and available QA commands.
2. Define the goal, non-goals, acceptance criteria, allowed paths, blocked
   actions, autonomy, and convergence limits.
3. Start durable JStack loop state and create the native Codex goal.
4. Run one Think -> Plan -> Build -> Review -> Test cycle.
5. Checkpoint current receipts and derived Git/artifact evidence.
6. Continue, request approval, stop on policy, or gather final evidence.
7. Finalize and mark the native goal complete only with a current completion
   receipt.

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

See [ADR 0002](adr/0002-jstack-loop-protocol.md) for protocol invariants and
[loop mastery](loop-mastery-system.md) for the training path.
