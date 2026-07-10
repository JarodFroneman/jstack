# JStack Mastery System

## Objective

Move from safe beginner operation to independent staff-level stewardship. The
system measures demonstrated behavior, not confidence, prompt fluency, or task
difficulty. Raw rubric score measures the work; assistance separately caps the
demonstrated level and advancement eligibility.

The canonical machine-readable curriculum is
`mastery/curriculum.v1.json`. The local profile is stored privately and
atomically under `~/.jstack/mastery/profile.json`.

## Stages

| Stage | Outcome | Required proof |
| --- | --- | --- |
| 0 Safe Operator | Orient safely in repos, git, runtimes, and environment boundaries | Correct orientation manifest, only required training-artifact writes, no exposed secrets |
| 1 JStack Reader | Trace commands, skills, schemas, handlers, policy, and package copies | Exact source trace and a detected planted inconsistency |
| 2 Scoped Maintainer | Deliver small coherent changes without collateral churn | Two accepted change attempts, focused QA receipts, reviewed diff |
| 3 Debugger/Test Author | Reproduce, isolate, fix, and preserve regression coverage | Failing-before/passing-after evidence and correct root cause |
| 4 MCP/Policy Engineer | Build conformant tools and fail-closed policy | External JSONL client, contract matrix, malformed-input suite |
| 5 Workflow Product Engineer | Keep all three modes consistent and task-first | Mode matrix, golden transcripts, concise instruction |
| 6 Packaging/Release Engineer | Reproduce install, upgrade, rollback, and artifact parity | Cross-platform matrix, parity check, rollback rehearsal |
| 7 Security/Reliability Auditor | Break unsafe paths, execution, dispatch, scans, and release claims | Threat model, adversarial suite, complete security receipt |
| 8 JStack Architect | Evolve contracts with invariants, compatibility, and migration safety | ADR, schema, migration/rollback rehearsal, independent review |
| 9 Staff Maintainer/Auditor | Lead unseen work and make correct evidence-based release calls | Two blind 90+ capstones with complete P0/P1 detection targets |

Each stage defines drills, mandatory artifacts, objective benchmarks, and hard
gates in the canonical curriculum.

## Scoring

Every assessed attempt is scored:

- correctness and benchmark completion: 30
- evidence and reproducibility: 25
- safety and security: 20
- scope and design judgment: 15
- explanation and transfer: 10

Raw score maps to level:

| Score | Level |
| --- | --- |
| below 50 | 0 Observed |
| 50-64 | 1 Guided |
| 65-79 | 2 Competent |
| 80-89 | 3 Independent |
| 90-100 | 4 Expert |

Assistance caps demonstrated level:

- observed work: level 0
- step-by-step guidance: level 1
- checklist-assisted work: level 2
- independent work: level 3
- independent novel review or teaching: level 4

A 95-point guided attempt remains Guided. Assistance is useful for learning but
is not independent proof. `independent_teach` also qualifies as independent
proof when the learner first solves the task and then accurately teaches or
reviews it.

Operational assistance definitions:

- observed: learner watches and does not make decisions
- guided: receives step-by-step solution direction
- checklist: receives a task-specific checklist or correction prompts
- independent: may use normal documentation and tools but receives no
  solution-specific hint, checklist, code, or corrective intervention
- independent teaching: independent work plus a novel explanation, review, or
  adaptation

An independent assessor did not coach or implement the attempt. It may be a
human or a fresh assessment agent given only submitted artifacts, evidence,
rubric, and seeded answer key. The same agent that coached the learner cannot be
the independent assessor.

Scoring anchors apply to each component:

| Component score | Anchor |
| --- | --- |
| 0 | Missing, fabricated, unsafe, or materially wrong |
| 50 | Partial result with major correction or evidence gaps |
| 80 | Correct result meeting mandatory benchmarks with only minor gaps |
| 100 | Complete, reproducible result with excellent transfer and no material gap |

## Evidence Manifest

Every recorded attempt includes:

- stage, drill, work type, and assistance level
- repository root, commit, clean state, and project fingerprint
- required artifact paths, hashes, types, and byte counts
- QA/security receipt verification where the stage requires it, otherwise an
  explicit not-applicable state
- five component scores and assessor citations
- hard-gate failures and residual risk
- score, raw level, assistance-capped level, and advancement eligibility

The server derives totals and advancement. It does not accept a caller-provided
final score.

## Advancement

Stages 0-3 require two consecutive independent attempts scoring at least 80.
Any guided, failed, hard-blocked, or otherwise ineligible intervening attempt
resets that streak because the server evaluates the latest two.

Stages 4-8 require three independent attempts:

- each at least 80
- mean at least 85
- at least two different commits
- at least one implementation and one audit

Stage 9 requires two blind capstones at 90 or above. Each must catch all seeded
P0 defects, at least 80 percent of seeded P1 defects, and make the correct
release go/no-go decision.

Fabricated/stale evidence, secret exposure, unapproved mutation, missing
mandatory artifacts, a missed seeded P0, or a false production-ready claim
blocks advancement regardless of score.

Required training artifacts live under `.jstack-training/`. They are the only
Stage 0 writes allowed; implementation, configuration, git-state, and
production mutation remain prohibited. `evidence-manifest.json` describes the
source evidence it cites. The server hashes that finished manifest as an
artifact, so the manifest never self-hashes.

Stages 6-9 should receive a retention check after a major JStack release.

## Learning Modes

`off` runs enterprise delivery with no visible lesson.

`embedded` is the default. After the engineering result, emit at most:

1. one mental model
2. one decision checkpoint
3. one next drill

`coach` permits interactive explanation and guided decisions.

`assessment` withholds hidden answers before an attempt and evaluates only the
submitted artifacts and evidence.

The command changes staffing, not the curriculum:

- single lead teaches one decision at a time
- smart subagents teach through specialist evidence and one material tradeoff
- full team teaches sequencing, conflict resolution, and go/no-go judgment

Do not emit role-by-role lectures during normal delivery.

## Starting Jay

1. Call `jstack_mastery_start` once.
2. Call `jstack_mastery_status` at the beginning of a training task.
3. Select a drill from the current learner stage.
4. Complete real project work through all task-risk gates.
5. Run QA and security checks required by the stage.
6. Produce every mandatory artifact.
7. Have an independent assessor cite concrete evidence.
8. Call `jstack_mastery_record`.
9. Repeat until the server's advancement policy passes.

When a real task is above the learner's stage, the Lead still applies every
advanced delivery gate. The learner completes only a current-stage assessment
slice before mutation or in a separate clean worktree. Lead/AI implementation
is not credited to the learner.

This is a local deliberate-practice record, not an accredited credential.
Its value comes from independent assessment and reproducible evidence.
