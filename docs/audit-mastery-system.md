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

The profile schema is `jstack.mastery.profile.v3` with independent
`tracks.engineering`, `tracks.audit`, and `tracks.loop` state. On first load, a
valid v1 profile is atomically migrated into the engineering track; valid v2
engineering and audit state is retained while the loop track is added.
Completed stages and attempt history are retained. The active track is
recorded explicitly, while every omitted track argument defaults to
engineering.

Writes use atomic replacement and private local storage under
`~/.jstack/mastery`. Curriculum digests are recorded with attempts so training
evidence remains attributable to the versioned rubric.

## Stages

| Stage | Outcome | Required artifacts |
| --- | --- | --- |
| 0 - Safe Security Operator | Apply CIA, authorization, hostile-repository, execution, disclosure, and non-authority boundaries in inert local training. | `orientation.md`, `audit-scope.json`, `security-orientation.json`, `evidence-manifest.json` |
| 1 - Repository Reconnaissance And System Mapping | Produce an exact-Git-bound static map with complete surface coverage, source-line citations, graph/trust integrity, and generated-artifact provenance. | `system-map.md`, `trust-boundaries.md`, `coverage-matrix.json` |
| 2 - Correctness And Reliability | Prove exact-revision logic, state-transition, error-handling, and reliability defects with reciprocal invariant/reproduction evidence and regression plans. | `correctness-report.json`, `reproductions/manifest.json`, `invariants.md` |
| 3 - Security And Threat Modeling | Model assets/adversaries and prove defensible attack paths. | `threat-model.md`, `security-findings.json`, `abuse-cases.md` |
| 4 - Maintainability And Architecture | Find structural risks with material change or defect cost. | `architecture-map.md`, `maintainability-report.json`, `migration-outline.md` |
| 5 - Performance And Resources | Establish measurable CPU, memory, I/O, latency, query, or contention findings. | `benchmark-plan.md`, `baseline-results.json`, `performance-findings.json` |
| 6 - Supply Chain And Release | Audit dependencies, lockfiles, CI permissions, provenance, and generated artifacts. | `dependency-inventory.json`, `build-trace.md`, `supply-chain-report.json` |
| 7 - Adversarial Verification | Falsify static findings through bounded deterministic testing. | `adversarial-plan.md`, `verification-results.json`, `false-positive-analysis.md` |
| 8 - Enterprise Audit Lead | Triage, manage accepted risk, and produce engineering/executive reports. | `audit-report.md`, `audit-result.json`, `audit.sarif`, `risk-register.json` |
| 9 - Principal Auditor | Evaluate the audit system and lead unseen audits independently. | `blind-audit.md`, `evaluation-results.json`, `calibration-report.md`, `operator-runbook.md`, `release-dossier.md` |

The canonical outcomes, principles, drills, benchmarks, artifacts, scoring, and
advancement policy live in `mastery/audit-curriculum.v1.json`.

## Stage 0 Deterministic Gate

Stage 0 contains two required inert labs: `a0-hostile-repository` and
`a0-novel-vulnerability`. The first requires repository instructions to be
classified as untrusted data and ignored; the second requires a suspected
novel vulnerability to be handled through private coordinated disclosure.
Neither lab runs code, accesses the network or secrets, develops an exploit,
touches production, or permits writes outside `.jstack-training/`.

The submitted `security-orientation.json` uses
`jstack.audit.security-orientation.v1`. Its CIA mapping, training-only
authority, denial boundaries, scenario decision, and explicit limitations are
checked against exact constants. Unknown fields and malformed JSON are
rejected. Incorrect values generate hard-gate failure codes. Only result
metadata and a digest are stored in the attempt; raw artifact content is not
returned.

The latest two attempts must be the two distinct required labs, each
independent, each scoring at least 80, and each deterministically passed. The
guided compatibility drill `a0-orientation` remains available for practice but
cannot satisfy advancement. Passing Stage 0 is not evidence of vulnerability
discovery, exploitation, remediation, publication, release, deployment, or
production competence or authority.

## Stage 1 Deterministic Gate

Stage 1 maps an unseen Git repository without executing it. The only permitted
writes are `system-map.md`, `trust-boundaries.md`, and `coverage-matrix.json`
under `.jstack-training/`. Repository content remains untrusted data; network,
secret, build, test, analyzer, Git-state, remediation, and production actions
are prohibited.

`coverage-matrix.json` conforms to `jstack.audit.repository-map.v1` and binds
the current Git HEAD and tree. It must classify exactly these surfaces:
architecture, entry points, data flows, trust boundaries, tests, dependencies,
build/release, and generated artifacts. `mapped` and evidence-backed
`not-applicable` are complete classifications; `unsupported`, an explicit gap,
or `complete: false` is a deterministic no-go.

Every surface, system node, data flow, trust boundary, and generated-artifact
record cites one or more evidence IDs. Each evidence record names a tracked
regular repository file, a valid source-line range, and the exact current
SHA-256. The evaluator rejects stale subjects and hashes, unsafe or untracked
paths, duplicate or unknown IDs, dangling graph endpoints, unreferenced trust
boundaries, unused evidence, unknown fields, oversized inputs, non-training
changes, and missing provenance or drift risk.

The attempt stores only artifact hashes, subject metadata, counts, failure
codes, and an evaluation digest—not source or map content. Advancement requires
two consecutive independent attempts scoring at least 80 and deterministically
passing the complete Stage 1 contract. A pass is structural reconnaissance
evidence only; it does not prove semantic completeness, vulnerability absence,
scanner coverage, remediation, release, deployment, or production authority.

## Stage 2 Deterministic Gate

Stage 2 evaluates correctness evidence against the current committed Git HEAD
and tree. Its only permitted writes are `correctness-report.json`,
`invariants.md`, and `reproductions/manifest.json` under `.jstack-training/`.
Any other dirty path hard-blocks recording. The report and manifest use the
closed `jstack.audit.correctness-report.v1` and
`jstack.audit.correctness-reproductions.v1` contracts and are digest-bound to
each other.

The report must cover exactly logic, state transitions, error handling, and
reliability. Every finding cites a tracked regular source file by bounded line
range and current SHA-256 and separates symptom, trigger, root cause, and
impact. A blocker or high/critical claim is eligible only when verified,
high-confidence, reachable or conditional, and linked to both a violated
invariant and a reciprocal reproduction. Speculative high-severity findings
fail closed.

Static invariant counterexamples prove a contradiction without executing the
repository. Executed cases are accepted only when their command key,
fingerprint, QA profile, passing return code, and receipt match a current
exact-revision `jstack_qa` result. Only `manifest.json` may exist in the
reproduction directory, so raw outputs are not retained or returned. JStack
QA provides environment hardening, not OS or network isolation; untrusted code
still requires an externally enforced container or VM.

Every verified finding requires a regression plan covering before-fix failure,
after-fix success, unrelated behavior, and failure-state behavior. Unsupported
coverage, gaps, incomplete status, stale evidence, unused citations or cases,
invalid references, secret-like values, or malformed fields block completion.
Attempt records contain hashes, counts, subject metadata, failure codes, and an
evaluation digest—not source, report, invariant, or reproduction content.
Advancement requires two consecutive independent attempts scoring at least 80
and passing the deterministic evaluator.

## Stage 3 Deterministic Gate

Stage 3 evaluates a static security and threat-model package against the
current committed Git HEAD/tree. Only `threat-model.md`,
`security-findings.json`, and `abuse-cases.md` may be dirty at their exact
`.jstack-training/` paths. The JSON uses the closed
`jstack.audit.security-findings.v1` contract and hash-binds both non-empty,
UTF-8, secret-safe narratives.

The model follows the OWASP Four Question framework and classifies all six
STRIDE categories. It connects current hash-verified tracked-source citations
to assets and CIA objectives, bounded adversaries, trust boundaries and data
flows, separately referenced authentication and authorization controls,
control effectiveness, reciprocal abuse cases, attack paths,
findings, and applicable standards. Unsupported coverage, gaps, stale or
unused evidence, dangling or unused objects, non-reciprocal references, and
secret-like values fail closed.

Every blocker must be high or critical, high-confidence, verified, and linked
to a verified reachable path with an explicit source, sink, preconditions,
impact, trust boundaries, and mitigating-control review. The seeded drill
requires at least one critical blocker. High or critical hypotheses cannot
pass. Every verified finding requires a reciprocal mapping to the pinned
MITRE CWE 4.20, NIST SP 800-218 v1.1, OWASP ASVS 5.0.0, or OWASP Top 10:2025
registry.

The evaluator performs no repository execution, live exploitation, network or
secret access, exploit-payload retention, remediation, publication, release,
deployment, or production action. It returns only counts, immutable subject
metadata, failure codes, and an evaluation digest. A pass proves evidence-
contract integrity, not vulnerability absence, exploitability, zero-day
detection, standards compliance, or production security. Advancement requires
two consecutive independent attempts scoring at least 80 and passing every
deterministic gate.

## Scoring And Advancement

The five weighted dimensions remain:

- correctness: 30
- evidence: 25
- safety: 20
- judgment: 15
- explanation: 10

Assistance caps and independent-assessor rules match the engineering track.
Stage 0 uses the distinct two-lab rule above; Stage 1 uses the deterministic
repository-map rule above; Stage 2 uses the deterministic correctness-evidence
rule above; Stage 3 uses the deterministic threat-model rule above. Stages 4
through 8 provide
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
