# JStack Program Protocol

## Purpose

A program coordinates a project-derived dependency graph of bounded JStack
child loops. It is for outcomes that cannot be represented honestly by one
short loop because they contain separately accepted deliverables, long waits,
different scopes or staffing, or final integration evidence.

The phase count is data, not product logic. A contract may contain any positive
number of phases up to the lower of its own limit and enterprise policy. A
large domain-specific project is one possible input, not a built-in workflow.

## Authority Model

- Codex Goal mode owns cross-turn continuation.
- Program state owns dependency scheduling, wait states, proof invalidation,
  active-time budget, and final acceptance.
- A bounded child loop owns one phase's implementation convergence.
- JStack Dev, Subagents, or Full Team owns phase execution only when that exact
  mode was approved.
- JStack Audit is an independent verifier, never an editing team.
- Human identities own human decisions. External systems own their artifacts.

The program never edits code, spawns agents, signs approvals, or authorizes a
release. It schedules only phases whose dependencies and pre-phase gates are
current.

## Contract Shape

A program contract includes:

- exact outcome, accountable owner, stakeholders, and non-goals;
- one to the policy maximum of phases;
- a cycle-free dependency DAG with stable IDs;
- phase goal, mode, autonomy, risk, paths, criteria, gates, outputs, and
  isolation declarations;
- final gates and machine-verifiable final acceptance criteria;
- maximum phases, parallel phases, and active minutes; and
- blocked actions that preserve release and production authority.

Program readiness returns at most three blocking questions per round and
requires exact-digest confirmation for multi-phase, parallel, or elevated-risk
contracts. The short-lived receipt binds the semantic input, Git state, policy,
tool version, and, for revisions, the prior contract digest.

## State Machine

| Status | Meaning | Valid next action |
| --- | --- | --- |
| `running` | At least one phase is ready or active | Schedule or continue a child |
| `waiting_human` | A current signed decision is missing | Wait, challenge, resolve |
| `waiting_external` | Fresh external evidence is missing or stale | Wait or register evidence |
| `paused` | Operator manually paused the program | Revalidate and resume |
| `blocked` | Rejection, budget, or context drift prevents progress | Revise or cancel |
| `validating` | Every phase and final gate is current | Gather final evidence |
| `completed` | Current final proof was issued | Revalidate receipt only |
| `cancelled` | Operator terminated the program | Preserve state |

Human/external waits and manual pauses stop the active-time clock. They are not
native Goal blocked status. One non-terminal program owns the orchestration
slot for a canonical Git repository.

## Phase Lifecycle

1. `jstack_program_next` selects dependency-ready phases.
2. Codex creates an exact bounded child loop using that phase contract.
3. `jstack_program_phase_bind` verifies child goal, mode, autonomy, risk,
   paths, criteria, inherited blocked actions, repository identity, and
   required worktree isolation.
4. The selected JStack delivery mode executes and verifies the child loop.
5. Child finalization issues a current loop receipt and durable attestation.
6. `jstack_program_phase_complete` cross-checks both, hashes declared outputs,
   and writes a phase proof.
7. After-phase gates must remain current before the phase satisfies dependants.

No summary, caller boolean, agent report, or human statement substitutes for a
child completion proof.

## Parallelism

Parallel scheduling is conservative. Every concurrently selected phase must:

- declare `parallel_safe=true` and `worktree_required=true`;
- execute in a linked Git worktree from the same common repository;
- have a disjoint top-level allowed-path scope; and
- fit the contract and policy parallel ceilings.

If any condition is absent, schedule serially. The current implementation does
not infer semantic merge independence from filenames.

## Retry Safety

Every state-changing program call requires a unique `operation_id`. Generate a
stable opaque value, persist it with the call, and reuse it only when retrying
the exact same operation and payload after a timeout. JStack records it inside
the snapshot-bound transaction.

Same key plus same payload returns current state with `idempotentReplay=true`.
The same key with another action or payload fails closed. Read-only status,
readiness, scheduling, and challenge calls do not consume operation IDs.

## Revision And Invalidation

Any material phase, dependency, mode, autonomy, risk, path, criterion, output,
gate, limit, or final-acceptance change requires a new exact readiness receipt
and accountable revision reference.

The revision engine retains unchanged current phase proof. It clears directly
changed phases and every transitive dependant. Every gate decision or evidence
record is cleared because it was bound to the prior program digest. Replacing
post-phase evidence or human decisions invalidates downstream completion that
relied on it.

## Persistence And Recovery

Private state lives at
`~/.jstack/programs/<project-hash>/<program-id>/`. Each program has:

- the current and versioned contracts;
- a snapshot bound to the latest event;
- a SHA-256 hash-chained JSONL event log; and
- a pending transaction journal for interrupted multi-file writes.

Contract, snapshot, event, pending-transaction, and project bindings are
validated on every load. Tampering fails closed. State is tamper-evident
against accidental changes, not protected from compromise of the same OS user.

## Completion

Program finalization rehashes declared outputs and revalidates durable child
attestations, every final gate, current final criteria, Git context, policy,
tool version, and baseline ancestry. Enterprise policy requires a current
release audit, security evidence, and deterministic integrated review.

A completed contract may be revalidated against a newer current Git subject.
The latest completion proof is replaced only after all unchanged contract
criteria pass again; prior proof remains in the immutable event history.

The resulting session receipt proves that exact current state only. It does not
authorize commit, push, merge, deployment, production mutation, or release.
