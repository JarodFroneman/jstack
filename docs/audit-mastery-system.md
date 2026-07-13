# JStack Audit Mastery

## Purpose

The audit track trains deliberate, evidence-backed auditing without replacing
the existing engineering curriculum. It is a local professional-development
record, not an accredited credential or external certification.

Use the existing mastery tools with `track="audit"`:

~~~text
jstack_mastery_start
jstack_mastery_status
jstack_mastery_record
~~~

Omitting `track` keeps the historical engineering behavior.

## Profile Migration

The profile schema is `jstack.mastery.profile.v2` with independent
`tracks.engineering` and `tracks.audit` state. On first load, a valid v1 profile
is atomically migrated into the engineering track. Completed stages and attempt
history are retained; the audit track starts at Stage 0. The active track is
recorded explicitly, while every omitted track argument defaults to
engineering.

Writes use atomic replacement and private local storage under
`~/.jstack/mastery`. Curriculum digests are recorded with attempts so training
evidence remains attributable to the versioned rubric.

## Stages

| Stage | Outcome | Required artifacts |
| --- | --- | --- |
| 0 - Safe Audit Operator | Orient without mutation, unapproved execution, or secret exposure. | `orientation.md`, `audit-scope.json`, `evidence-manifest.json` |
| 1 - System Mapping | Map architecture, entry points, data flow, trust boundaries, tests, dependencies, and release paths. | `system-map.md`, `trust-boundaries.md`, `coverage-matrix.json` |
| 2 - Correctness And Reliability | Prove logic, state, error-handling, and reliability defects. | `correctness-report.json`, `reproductions/`, `invariants.md` |
| 3 - Security And Threat Modeling | Model assets/adversaries and prove defensible attack paths. | `threat-model.md`, `security-findings.json`, `abuse-cases.md` |
| 4 - Maintainability And Architecture | Find structural risks with material change or defect cost. | `architecture-map.md`, `maintainability-report.json`, `migration-outline.md` |
| 5 - Performance And Resources | Establish measurable CPU, memory, I/O, latency, query, or contention findings. | `benchmark-plan.md`, `baseline-results.json`, `performance-findings.json` |
| 6 - Supply Chain And Release | Audit dependencies, lockfiles, CI permissions, provenance, and generated artifacts. | `dependency-inventory.json`, `build-trace.md`, `supply-chain-report.json` |
| 7 - Adversarial Verification | Falsify static findings through bounded deterministic testing. | `adversarial-plan.md`, `verification-results.json`, `false-positive-analysis.md` |
| 8 - Enterprise Audit Lead | Triage, manage accepted risk, and produce engineering/executive reports. | `audit-report.md`, `audit-result.json`, `audit.sarif`, `risk-register.json` |
| 9 - Principal Auditor | Evaluate the audit system and lead unseen audits independently. | `blind-audit.md`, `evaluation-results.json`, `calibration-report.md`, `operator-runbook.md`, `release-dossier.md` |

The canonical outcomes, principles, drills, benchmarks, artifacts, scoring, and
advancement policy live in `mastery/audit-curriculum.v1.json`.

## Scoring And Advancement

The five weighted dimensions remain:

- correctness: 30
- evidence: 25
- safety: 20
- judgment: 15
- explanation: 10

Assistance caps and independent-assessor rules match the engineering track.
Early stages require consecutive independent passes. Stages 4 through 8 provide
separate audit and bounded implementation drills and require repeated evidence
across both work types and repository states. Stage 9 requires two independent,
assessor-signed blind capstones at 90 or above on distinct challenge subjects.

Audit attempts at Stage 8 and above require a current, complete audit receipt.
Stage 9 additionally requires complete scored fixture coverage, correct
unsupported/complete coverage classification, every seeded P0, at least 80
percent P1 recall, no severity under-ranking or priority miscalibration, no
false P0, at least 80 percent precision, a duplicate rate at most 5 percent,
correct release decisions, deterministic reruns, and no hard-gate failure.

`evaluation-results.json` uses
`jstack.audit.benchmark-evaluation.v1` and contains `primarySubmission` and
`repeatSubmission`, each conforming to
`jstack.audit.benchmark-submission.v1`. The MCP loads the pinned local corpus,
derives both result sets, and compares their semantic result digests. Audit
Stage 9 rejects caller-supplied aggregate `capstone_results`; only scorer-derived
metrics are recorded in `benchmarkEvaluation`.

The bundled corpus is synthetic, inert, offline, digest-pinned, and transparent.
Because its answer key ships with the scorer, it is a practice/calibration
benchmark and cannot itself prove blindness. Eligible Stage 9 attempts require
an assessor attestation signed with a runtime-only
`JSTACK_AUDIT_ASSESSOR_HMAC_KEY`. The attestation binds the exact artifact,
rubric, commit, benchmark-evaluation digest, assessor, and unseen challenge
digest; two attempts must use distinct challenge digests. The key is never
returned or stored in the profile. JStack still treats this as a local
professional-development record, not an external credential.

## Hard Gates

Advancement is denied for fabricated or stale evidence, secret exposure,
unapproved mutation/execution, missing mandatory artifacts, missed seeded P0,
false production-ready claims, or an audit pass issued with incomplete required
coverage.

Benchmark metrics describe only the retained seeded corpus. They are not proof
that every real-world defect will be found. Performance claims require a pinned
external harness and retained raw measurements.
