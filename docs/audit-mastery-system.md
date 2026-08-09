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
| 5 - Performance And Resources | Prove one exact-revision, signed-sample performance defect and verify one separately authorized committed correction without regressing a guardrail. | `benchmark-plan.md`, `baseline-results.json`, `performance-findings.json` |
| 6 - Supply Chain And Release | Audit dependencies, lockfiles, CI permissions, provenance, and generated artifacts. | `dependency-inventory.json`, `build-trace.md`, `supply-chain-report.json` |
| 7 - Dynamic And Adversarial Verification | Challenge static findings with exact-revision signed deterministic captures, reciprocal false-positive analysis, complete category classification, QA/security bindings, and a separately committed harness comparison. | `adversarial-plan.md`, `verification-results.json`, `false-positive-analysis.md` |
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

## Stage 4 Deterministic Gate

Stage 4 evaluates architecture and maintainability evidence without turning
Audit into an editing agent. Its only permitted dirty paths are
`architecture-map.md`, `maintainability-report.json`, and
`migration-outline.md` beneath `.jstack-training/`. The JSON uses the closed
`jstack.audit.maintainability-report.v1` contract and hash-binds both non-empty,
UTF-8, secret-safe narratives.

The report classifies exactly module boundaries, dependency direction,
contracts and compatibility, change amplification, testability, and migration
risk. Revision-tagged citations are loaded from immutable baseline or
candidate Git objects and verified by line range and SHA-256. Components,
dependencies, contracts, change scenarios, findings, remediations, and
compatibility assessments use reciprocal closed references. Change-scenario
touch-point counts must exactly match the affected component set. Findings
must describe material change cost, defect risk, compatibility risk,
testability risk, or migration risk; style-only preferences cannot pass as
maintainability defects.

The `a4-architecture` drill is static: baseline and candidate are the same
current commit, remediations remain proposed, and QA bindings are forbidden.
The `a4-remediation` drill does not authorize Audit to edit. A separate
development workflow must produce and commit the candidate first. The
evaluator then requires a strict ancestor baseline, reconciles every reported
changed path with the exact Git diff, requires exactly one implemented and
verified remediation for a resolved finding, checks every contract at both
revisions, blocks breaking or unsupported compatibility, and verifies a
current passing exact-candidate `jstack_qa` receipt.

The evaluator executes no repository code, accesses no network or secrets,
and returns only subject metadata, counts, failure codes, and an evaluation
digest—not source, finding, root-cause, architecture-map, or migration content.
Unsupported coverage, unresolved gaps, unused objects, stale evidence,
malformed references, speculative high severity, or non-training changes fail
closed. A pass proves contract and receipt integrity only; it does not prove
semantic correctness, behavior preservation, architecture quality,
compatibility, vulnerability absence, remediation safety, release readiness,
or production authority.

Advancement requires three independent deterministic passes across at least
two commits. Every score must be at least 80, the mean must be at least 85, and
the attempt set must include both named Stage 4 drills.

## Stage 5 Deterministic Gate

Stage 5 validates performance evidence without turning Audit into an execution
or optimization agent. Its only permitted dirty paths are
`benchmark-plan.md`, `baseline-results.json`, and
`performance-findings.json` beneath `.jstack-training/`. The JSON uses the
closed `jstack.audit.performance-results.v1` and
`jstack.audit.performance-findings.v1` contracts; captured samples use
`jstack.performance.capture.v1`.

Benchmark execution happens before the Audit assessment in a separately
authorized trusted development or QA workflow. `jstack_performance_capture`
accepts only a discovered project command at an exact reviewed Git revision,
fingerprint, and policy. It supplies a fixed output path and workload binding,
closes stdin, scrubs the environment, forwards no secrets, uses an isolated
HOME, bounds time and output, and rejects Git-visible tracked or non-ignored
repository mutation. Ignored cache and build outputs remain outside that
guarantee. It then signs
the Git tree, command fingerprint, workload digest, local environment digest,
normalized sample digest, metric count, and measured-iteration count. This
uses direct MCP receipt passing—never a user-generated approval token or
terminal-paste ceremony. The local runner retains the current user's
filesystem and network privileges, so untrusted code still requires an
external container or VM.

The workload records a deterministic seed, input digest, concurrency, warmups,
measured iterations, timeout, critical path, and realism rationale. Every
capture contains exactly one primary metric and at least one guardrail metric.
All samples are retained; warmups are excluded; outliers are not removed; and
JStack recomputes mean and nearest-rank median/p95 values. Latency, throughput,
CPU, memory, I/O, query, and contention must each be measured or explicitly
not applicable. Unsupported coverage and gaps fail closed. A current passing
exact-candidate `jstack_qa` receipt is required for both drills because
performance evidence does not prove correctness.

`a5-performance` uses one signed capture with baseline and candidate equal to
the current commit. It requires one source-cited bottleneck, one declared
statistic and budget that the baseline violates, a proposed remediation, and
planned guardrails. `a5-regression` verifies a candidate already changed and
committed by a separate workflow. Its baseline must be a strict ancestor; the
two captures must use the same workload, command, environment, metric IDs,
units, directions, and roles; reported paths must equal the Git diff; the
candidate must meet the budget with a positive improvement recomputed from the
retained samples; and every guardrail must remain within its declared maximum
regression.

The evaluator reads immutable Git blobs and signed receipts and returns only
subject metadata, counts, failure codes, and a digest—not source narratives,
command output, artifacts, or performance samples. A pass proves bounded
protocol integrity, not workload realism, measurement accuracy, universal
performance, production capacity, optimization safety, release readiness, or
production authority. Advancement requires three independent deterministic
passes across at least two commits, every score at least 80, mean at least 85,
and both named Stage 5 drills.

## Stage 6 Deterministic Gate

Stage 6 validates supply-chain and build evidence without turning Audit into a
dependency-resolution, scanner-execution, hardening, or release agent. Its
only permitted dirty paths are `dependency-inventory.json`, `build-trace.md`,
and `supply-chain-report.json` beneath `.jstack-training/`. The JSON uses the
closed `jstack.audit.dependency-inventory.v1` and
`jstack.audit.supply-chain-report.v1` contracts; both are bound to exact
baseline and candidate Git commits and trees, and the build trace is non-empty,
UTF-8, secret-safe, and hash-bound.

JStack enumerates the complete tracked path set at both revisions, applies a
closed cross-ecosystem classifier, reloads every classified Git blob, and
recomputes its SHA-256 and size. Omitted or invented manifests, lockfiles,
dependency policies, build configurations, GitHub workflows, provenance files,
or conventional generated artifacts fail. The structural classifier supports
major implementation-language ecosystems but does not prove complete semantic
or transitive dependency resolution.

Every closed-form GitHub Actions `uses:` reference and top-level permission
declaration is independently parsed and exactly reconciled. Dynamic or
unparseable references fail closed. Mutable references, implicit or
unsupported permissions, unbounded writes, missing provenance, and generated-
copy drift require reciprocal verified findings. The graph traces source,
configuration, and dependency materials to every candidate artifact. Every
candidate artifact has explicit provenance, and every discovered generated
copy has a same-revision exact-copy, drift, or unverifiable classification.

Dependency advisory evidence must come from a separately approved curated
adapter bound to the exact audit subject. The final audit receipt carries only
sanitized adapter identity/status/version, subject validation, zero return
code, and evidence digests. Stage 6
requires a current complete same-session receipt with `supply-chain` coverage
and passed, no-mutation `dependency-analysis` evidence, plus current passing
receipts for every discovered QA command. Scanner output and secret values are
never accepted as mastery artifacts. The local adapter runner is not an OS or
network sandbox; untrusted repositories require external isolation.

The optional cross-ecosystem adapter invokes OSV-Scanner in offline mode using
a pre-provisioned external database named by
`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. JStack binds the resolved database
path and executable identity into the exact subject, rejects a database inside
the repository, and never downloads advisory data.

`a6-supply-chain` is static: baseline equals candidate, findings remain open,
and remediations remain proposed. `a6-hardening` verifies one candidate already
changed and committed by a separate authorized workflow. Its baseline is a
strict ancestor, the reported paths equal the Git diff, and exactly one
finding/control is resolved and implemented with baseline/candidate evidence
and matching QA. The evaluator returns only metadata, counts, failure codes,
and a digest. A pass proves bounded protocol integrity—not complete dependency
semantics, current advisory coverage, reproducible builds, artifact
authenticity, vulnerability absence, release readiness, or production
authority. Advancement requires three independent deterministic passes across
at least two commits, every score at least 80, mean at least 85, and both named
Stage 6 drills.

## Stage 7 Deterministic Gate

Stage 7 challenges static findings with bounded dynamic evidence without
turning Audit into an execution, exploit, harness-development, or remediation
agent. Its only permitted dirty paths are `adversarial-plan.md`,
`verification-results.json`, and `false-positive-analysis.md` beneath
`.jstack-training/`. The result envelope uses
`jstack.audit.adversarial-verification.v1`; each retained capture uses the
closed `jstack.adversarial.capture.v1` protocol.

One declared campaign binds the plan digest, deterministic seed, input-corpus
digest, target-scope digest, timeout, maximum case count, two-rerun rule,
external-effect policy, and isolation policy. Captures must come from
session-local `jstack_adversarial_capture` receipts produced by a separately
authorized trusted development or QA workflow. Each receipt binds an exact Git
commit and tree, current policy, one discovered command and fingerprint,
campaign, local environment, normalized capture, case-set digest, and
outcome-set digest. Receipts pass directly between MCP tools; users do not copy
tokens, signer commands, or confirmation digests into a terminal.

The capture protocol carries only bounded identifiers, categories,
classifications, counts, and SHA-256 digests. It excludes raw test inputs,
payloads, source, secrets, stdout, and stderr. At least four cases across at
least three categories are required, and every case must report identical
status and outcome digests across exactly two runs. All eight categories are
explicitly classified as tested or not applicable: negative input, boundary
value, invariant, fault injection, authorization, state transition,
differential, and resource boundary. Unsupported coverage and unresolved gaps
fail closed.

Every candidate case maps to exactly one falsifiable hypothesis. The package
must contain static-finding and dynamic-observation origins, at least one
confirmed dynamic observation, and both confirmed and refuted dispositions.
Every hypothesis has exactly one reciprocal supported or false-positive
assessment. A current passing receipt for every discovered QA command and a
current complete passing security receipt remain mandatory.

`a7-adversarial` uses one current capture with baseline equal to candidate and
observes an existing harness only. `a7-harness` verifies a candidate already
implemented and committed by a separate authorized workflow: the baseline is
a strict ancestor, reported changed paths equal the Git diff, captures share
campaign/command/environment bindings, at least one case is added, no case is
removed, and all shared case contracts and outcomes remain stable. The
evaluator returns only metadata, counts, failure codes, and a digest.

Local capture uses a scrubbed environment and isolated HOME but is not an OS
or network sandbox and does not enforce the claimed absence of external
effects. Untrusted or active security testing requires an externally enforced
container or VM plus explicit target authorization. A Stage 7 pass proves only
bounded protocol integrity—not vulnerability absence, exploitability,
zero-day detection, universal behavior, release readiness, production safety,
or production authority. Advancement requires three independent deterministic
passes across at least two commits, every score at least 80, mean at least 85,
and both Stage 7 drills.

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
rule above; Stage 3 uses the deterministic threat-model rule above; Stage 4
uses the deterministic architecture rule above; Stage 5 uses the signed
performance-evidence rule above; and Stage 6 uses the deterministic supply-
chain/build-integrity rule above; and Stage 7 uses the signed deterministic
adversarial-verification rule above. Stage 8 provides separate audit and
bounded implementation drills and requires repeated evidence across both work
types and repository states. Stage 9 requires two independent,
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
that every real-world defect will be found. Performance claims require a
closed workload, retained raw measurements, signed capture binding, and an
honest statement of environment and representativeness limits.
