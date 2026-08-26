# Stage 19 — Empirical Proof Program

## Current result

| Item | Value |
| --- | --- |
| Study state | `NOT_MEASURED` |
| Comparative claim | None |
| Superiority claim | Not supported |
| Execution authority | None |
| Advance gate | **IMPLEMENTED, NOT YET EMPIRICALLY PASSED** — the protocol exists; the study has not run |
| Release state | Protocol packaged in `v0.11.0`; study execution remains separately authorized and has not occurred |

Stage 19 adds a development-only, network-free protocol under
`unified_os_evals/`. It is deliberately excluded from the installed MCP,
umbrella plugin, dedicated plugins, commands, skills, and runtime authority.

## Preregistered design

The study has four conditions:

1. base agent;
2. pinned gstack;
3. pinned JStack baseline; and
4. the combined JStack candidate.

It covers 14 task classes and three repetitions per condition, producing 168
preregistered cells and 42 paired task/repetition groups. The classes cover
trivial UI, frontend, backend, cross-cutting, debugging, browser QA, design,
API compatibility, authentication, security, dependency, finance,
multi-phase, and release work.

The 16 closed metrics include completion, regressions, escaped defects, scope
drift, unauthorized actions, human intervention, evidence completeness,
browser-QA value, false positives, latency, tokens, repeatability, developer
experience, candidate-code mutation, Git mutation, and deployment observation.
Missing, failed, blocked, and timed-out cells remain in the denominator.

## Reproducibility and binding

The template binds:

- JStack baseline `49cf545d940c43b394ea35ed78b5ab5742d7bcf7`;
- gstack commit `ad8400543cd9ce8d07641362db48d44a95417e33`;
- gstack tree `993294b0a09f5265d2d5af6d2fb8234ae2efe450`; and
- MIT licence status.

An execution plan additionally requires the exact combined candidate commit,
tree, and environment digest. Results must match one preregistered cell and
the exact plan digest. Duplicate, altered, or foreign results fail closed.

## Privacy, cost, and claim policy

Results store metrics and evidence digests only. Raw prompts, source code,
model output, command output, secrets, reviewer identity, and hidden reasoning
are prohibited. The scorer does not call a model, network, repository,
provider, installer, Git, release, or deployment surface.

Unknown metrics are `NOT_MEASURED`. Even a complete metric set only makes a
result eligible for independent interpretation; the protocol never generates
a superiority claim automatically. A real study needs a separately approved
budget, task fixtures, environment, provider credentials, reviewers,
statistical analysis, and action permissions.

## Artifacts and verification

- `unified_os_evals/study-template.v1.json`;
- `unified_os_evals/protocol.py`;
- `unified_os_evals/schemas/study-template.v1.schema.json`;
- `unified_os_evals/schemas/result.v1.schema.json`;
- `scripts/run_unified_os_evaluation.py`; and
- `tests/test_unified_os_evals.py`.

Focused tests validate all 168 cells, closed schemas, no-claim behavior with
zero or complete-but-unmeasured results, raw-content rejection, retained
unauthorized-action metrics, plan/result tampering, and the validation CLI.

No empirical result has been fabricated. JStack must not claim that the
combined architecture outperforms any comparison condition until a separate,
reproducible study produces reviewable evidence.
