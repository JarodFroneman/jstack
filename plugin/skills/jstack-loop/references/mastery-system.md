# Loop Engineering Mastery

Use the `loop` track with `jstack_mastery_start`, `jstack_mastery_status`, and
`jstack_mastery_record`. This is a deliberate-practice and evidence system, not
an external credential. Advancement comes from repeated independent work, not
from completing one successful task.

## Mastery Model

Every attempt is scored on correctness (30%), evidence (25%), safety (20%),
judgment (15%), and explanation (10%). Assistance caps the demonstrated level:
observed work cannot prove independence, guided work cannot prove competence,
and expert credit requires independent execution plus the ability to teach the
reasoning.

Promotion rules:

- Stages 0-3: two consecutive independent attempts scoring at least 80.
- Stages 4-8: three independent attempts across at least two commits, each at
  least 80 with a mean of at least 85, covering implementation and audit work.
- Stage 9: two independently attested blind capstones on distinct challenge
  subjects, each scoring at least 90, with every seeded P0 and at least 80% of
  seeded P1 defects found and both continuation and release decisions correct.

Unbounded continuation, fabricated or stale evidence, silent staffing or
autonomy escalation, policy bypass, and false complete or blocked claims are
hard failures at every stage.

## Progressive Stages

### Stage 0: Loop Observer

Outcome: distinguish prompts, workflows, native goals, bounded loops,
checkpoints, completion, and stop conditions.

Core principles: a loop is a controlled state machine; continuation is not
verification; permissions remain active; every loop needs a terminal state.

Benchmark: identify the owner, state, evidence, limits, approvals, and terminal
outcomes of an existing loop without changing the project. Produce a loop
anatomy and boundary map.

### Stage 1: Goal Contract Designer

Outcome: turn an ambiguous request into observable criteria, non-goals, scope,
risk, approvals, and stop conditions.

Core principles: observable outcomes; explicit non-goals; least scope; risk
selects evidence; a changed target is a contract revision.

Benchmark: every criterion has a named verifier, subjective or gameable
criteria are rejected, and no L3 or team approval is inferred. Produce a goal
contract and criteria review.

### Stage 2: Minimum Viable Loop Builder

Outcome: run a low-risk loop through start, one meaningful iteration,
checkpoint, finalization, and user stop.

Core principles: smallest coherent iteration; current evidence only; explicit
terminal states; completion is receipt-bound.

Benchmark: unmet criteria fail closed, a passing QA receipt is current, and a
stop releases the write lease. Produce a contract, event summary, and
verification record.

### Stage 3: State And Recovery Engineer

Outcome: preserve durable state integrity, exclusive ownership, and recovery
across interrupted writes and process restarts.

Core principles: atomic state; snapshot and contract binding; hash-chained
events; one writer; corruption fails closed.

Benchmark: recover a journaled interruption, reject event/snapshot/contract
tampering, and distinguish live, stale, and released leases. Produce a recovery
runbook, tamper results, and state invariants.

### Stage 4: Verification Engineer

Outcome: design acceptance evidence that is current, reproducible, and
separate from maker assertions.

Core principles: maker-checker separation; evidence is state-bound; tests prove
specific claims; human judgment is named; stale receipts are invalid.

Benchmark: explain and exercise QA, security, audit, review, artifact, and human
approval verifiers; reject stale, malformed, incomplete, and caller-asserted
evidence. Produce an evidence contract, verification matrix, and adversarial
results.

### Stage 5: Convergence Engineer

Outcome: diagnose and stop stagnation, repeated failure, oscillation, cosmetic
progress, and budget overrun.

Core principles: progress is observable; repeated failures require a new
hypothesis; oscillation is a stop signal; circuit breakers invite judgment.

Benchmark: every breaker has a deterministic trigger, cosmetic edits cannot
reset convergence, and approval waits remain distinct from policy stops and
success. Produce a convergence model, breaker tests, and decision log.

### Stage 6: Program Orchestration Engineer

Outcome: compose bounded loops into a project-derived Program -> Phase DAG with
explicit dependencies, gates, outputs, final acceptance, and approved delivery
modes.

Core principles: phase count follows the project; the program owns dependency
proof; each loop owns phase convergence; the selected workflow owns execution;
staffing is authoritative; audit is read-only.

Benchmark: variable-size programs use one engine, cycles and unjustified edges
fail, child contracts match exactly, single-lead never spawns agents, team
modes carry explicit approval references, writer scopes do not overlap, and
acceptance remains stable. Produce a program contract, dependency rationale,
composition matrix, coordination packets, and mode test results.

### Stage 7: Autonomy Security Engineer

Outcome: threat-model and enforce scope, worktree, secret, signed identity,
external evidence, approval, tool, protected-path, and release boundaries.

Core principles: least privilege; L3 is earned and explicit; worktrees isolate
writes; humans sign their own decisions; external evidence is fresh and
hashed; protected actions stay blocked; incomplete security evidence is no-go.

Benchmark: all seeded critical bypasses are blocked, L3 rejects non-worktree or
non-low-risk starts, forged/stale/wrong-role gates fail, changed evidence
invalidates dependants, hidden Git state cannot conceal changes, and completion
cannot authorize release. Produce a threat model, autonomy policy, identity
boundary, evidence-registry results, and current security results.

### Stage 8: Loop Platform Architect

Outcome: evolve loop/program schemas, persistence, migrations, observability,
idempotency, packaging, and rollback without losing compatibility or trust
semantics.

Core principles: version durable contracts; preserve evidence in migrations;
make retries idempotent; keep one canonical source; observe decisions; rehearse
rollback.

Benchmark: migrations are atomic, interrupted program writes recover,
operation-key collisions fail closed, generated artifacts remain synchronized,
cross-platform install and rollback pass, and current QA, security, and audit
receipts support the result. Produce an ADR, migration plan, compatibility
results, and rollback runbook.

### Stage 9: Principal Loop Engineer

Outcome: design, operate, audit, and defend production-grade bounded loops and
multi-phase programs on unseen goals while making correct continuation, stop,
intervention, and release decisions.

Core principles: reduce uncertainty; bound autonomy; verify before declaring;
stop honestly; own operations; teach transferable judgment.

Benchmark: complete two distinct blind capstones with all seeded P0 and at
least 80% of P1 defects found, correct continuation and release decisions,
verified recovery, and a complete evidence dossier. Each attempt requires a
hashed `capstone-evaluation.json`, a current passing audit receipt, and an
independent HMAC-signed attestation bound to the exact artifacts, Git state,
assessment, and challenge. Produce the capstone contract, evaluation, event
dossier, adversarial report, operator runbook, and release decision.

## Practice Cycle

1. Read the current stage and select one listed drill.
2. State the hypothesis, evidence target, and hard gates before working.
3. Perform the work at the declared assistance level.
4. Commit Stage 2+ evidence before recording it; gather current receipts.
5. Have the assessor cite exact artifacts and score all five rubric dimensions.
6. Record the attempt. Review failed gates before repeating the drill.
7. Advance only when `jstack_mastery_status` derives that the promotion policy
   is satisfied.

For Stage 9, the independent assessor configures
`JSTACK_LOOP_ASSESSOR_HMAC_KEY` with at least 32 bytes and signs the documented
attestation body. Never place that key in the repository or a mastery artifact.

The capstone evaluation schema is `jstack.loop.capstone-evaluation.v1` and
contains non-negative `p0Total`, `p0Found`, `p1Total`, and `p1Found` integers
plus boolean `continuationDecisionCorrect`, `releaseDecisionCorrect`,
`recoveryVerified`, and `evidenceComplete` fields. Unknown fields fail closed.

The attestation schema is `jstack.loop.capstone-attestation.v1`. Its body
contains `assessorId`, `challengeId`, a `sha256:` challenge digest, the exact
attempt and evaluation digests, timezone-aware `issuedAt` and `expiresAt`, and
true `blind` and `independent` fields. Canonicalize the body as compact
ASCII JSON with sorted keys, compute HMAC-SHA-256 with the assessor key, and add
the result as `signature="sha256:<hex>"`. The attestation expires within 30
days, and the two mastery capstones must use different challenge digests.
