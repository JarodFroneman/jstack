# ADR 0002: Bounded Loop Engineering Protocol

- Status: Accepted
- Date: 2026-07-15
- Target release: 0.4.0

## Context

JStack delivery modes can plan, build, review, test, and assess release
readiness, but they do not by themselves define a durable cross-turn goal,
convergence policy, or evidence-bound terminal decision. A naive "repeat until
done" prompt is unsafe because it has no stable completion contract, state,
budget, ownership boundary, or circuit breaker.

Codex already provides native Goal mode for continuation. JStack should not
duplicate or misrepresent that platform runtime. It should define the durable
engineering contract that Goal mode follows.

## Decision

Add `/jstack-loop` as a fifth workflow in 0.4.0.

The loop is a composition layer:

- Codex Goal mode owns continuation across turns.
- JStack Loop owns the goal contract, Git binding, path scope, durable state,
  convergence policy, evidence validation, and terminal decision.
- JStack Dev, Subagents, or Full Team owns execution, selected explicitly for
  the life of the contract.
- JStack Audit remains an independent read-only verifier.

The MCP exposes start, status, checkpoint, revise, stop, and finalize tools. It
does not accept arbitrary command strings and does not prompt or spawn itself.

## Invariants

1. Write-capable loops start from a clean committed Git state.
2. One write-capable loop holds a resolved Git-checkout lease at a time;
   separately linked worktrees remain isolated checkout boundaries.
3. L3 requires explicit approval, low risk, bounded paths, a linked worktree,
   and QA, security, audit, and review criteria.
4. Contracts and revisions are versioned; completion evidence is invalidated
   when the target changes.
5. Events are append-only in meaning, atomically persisted, sequence checked,
   and SHA-256 hash chained; the current snapshot digest is bound into the
   latest event.
6. Completion evidence must match current root, baseline, HEAD, project
   fingerprint, policy digest, tool version, and server session.
7. Scope or policy violations stop the loop. Repeated failure, stagnation,
   oscillation, time, iteration, change limits, and policy/tool-version drift
   require an approved revision before work resumes.
8. A loop completion receipt never authorizes commit, push, deployment, or
   release.
9. Only native Goal mode applies its three-consecutive-turn blocked rule. MCP
   checkpoint counts are not represented as Goal turns.

## Persistence

Loop state lives outside the repository under
`~/.jstack/loops/<project-hash>/<loop-id>/` with private permissions. Each loop
contains the current contract, versioned contract revisions, a snapshot, and a
hash-chained JSONL event record. Historical revisions are versioned and
validated against the event chain; they are tamper-evident, not protected from
the same operating-system user. Repository source stays free of live loop
state, and packaged code never contains user-specific state.

## Rejected Alternatives

- Unbounded self-prompting: no reliable completion or safety boundary.
- A separate Node agent runtime: duplicates Codex Goal mode and adds a second
  authority for permissions and state.
- Markdown-only state: easy to alter and impossible to validate reliably.
- Caller-supplied success booleans: assertions are not evidence.
- Automatic single-lead to team escalation: violates command authority and
  user consent.
- Importing an upstream repository as a runtime dependency: unnecessary supply
  chain and compatibility surface.

## Prior Art

The initial planning brief referenced the
[14-step loop-engineering roadmap](https://x.com/0xcodez/status/2064374643729773029)
as a learning model, not as executable source or a runtime dependency.

The staged learning model and loop/goal separation were informed by
[cobusgreyling/loop-engineering](https://github.com/cobusgreyling/loop-engineering)
and [cobusgreyling/goal-engineering](https://github.com/cobusgreyling/goal-engineering).
JStack adapts those concepts to its own Python MCP, evidence receipts, Codex
Goal semantics, packaging, and mastery system. No upstream runtime or source
code is copied. The reviewed reference commits were
`6a670357ab748e20d14752bda82999a97f8afc6f` and
`325886e0195e72a0a409e8cc42e6fe691be457e7`, respectively.

## Consequences

JStack can now persist a bounded definition of done across Codex turns and
compose it with every delivery mode. The cost is stricter setup: write loops
need a clean Git state, observable criteria, bounded paths, and final current
evidence. This friction is intentional.
