# ADR 0016: Signed Performance Evidence At Audit Stage 5

- Status: Accepted
- Date: 2026-08-05
- Target release: 0.10.0-alpha.6

## Context

Audit mastery Stages 0 through 4 established safe operation, repository
mapping, correctness, threat modelling, and architecture evidence. Stage 5
must teach performance and resource judgment without accepting prose such as
“40% faster,” comparing different workloads or machines, silently discarding
outliers, or allowing the read-only Audit workflow to execute and optimize
repository code.

A benchmark number is only meaningful when its revision, command, workload,
environment, samples, statistic, and correctness boundary are known. Baseline
and candidate evidence must remain comparable, while the implementation path
must remain outside Audit. A deterministic evaluator can validate those
bindings and recompute claims, but it cannot determine whether a synthetic
workload represents production or whether the local host produced perfectly
accurate measurements.

## Decision

1. Ship closed `jstack.performance.capture.v1`,
   `jstack.audit.performance-results.v1`, and
   `jstack.audit.performance-findings.v1` contracts plus one hash-bound
   benchmark plan.
2. Permit only `.jstack-training/benchmark-plan.md`,
   `.jstack-training/baseline-results.json`, and
   `.jstack-training/performance-findings.json` to be dirty during an attempt.
3. Add `jstack_performance_capture` as a developer/QA evidence tool. It is not
   Audit execution authority and accepts only a discovered project command at
   an exact trusted revision, project fingerprint, and policy digest.
4. Use direct MCP trust parameters and session receipts. Never require a
   user-generated key, approval token, challenge file, or terminal paste.
5. Run with stdin closed, no shell, a scrubbed environment, no forwarded
   secrets, an isolated HOME, a fixed external output file, and process-group
   time/output limits. Reject Git-visible tracked or non-ignored repository
   mutation; ignored caches and build outputs remain outside this guarantee.
6. Open the output without following symlinks where supported, verify file
   identity, bound its size, reject duplicate JSON keys and secret-like values,
   and accept only finite non-negative samples under the closed protocol.
7. Sign the exact Git commit/tree, discovered-command fingerprint, workload
   digest, local-environment digest, normalized capture digest, metric count,
   sample count, policy, JStack version, and live server session.
8. Require the workload to declare input digest, deterministic seed,
   concurrency, warmups, measured iterations, timeout, critical path, and
   realism rationale. Retain every measured sample; exclude warmups; use no
   outlier removal; recompute mean and nearest-rank median/p95.
9. Require exactly one primary metric and at least one guardrail metric. Cover
   latency, throughput, CPU, memory, I/O, query, and contention with measured
   or evidence-backed not-applicable states. Unsupported coverage or gaps are
   a no-go.
10. Keep `a5-performance` measurement-only: baseline equals candidate, one
    signed current capture proves one explicit budget violation, remediation
    remains proposed, and guardrails remain planned.
11. Keep optimization authority outside Audit. For `a5-regression`, accept only
    a candidate already changed and committed by a separate authorized
    workflow. Require a strict ancestor baseline, exact Git-diff reconciliation,
    comparable signed captures, a met budget, positive recomputed improvement,
    and every guardrail within its declared maximum regression.
12. Require current passing exact-candidate `jstack_qa` evidence for both
    drills. Performance evidence never substitutes for correctness evidence.
13. Return only subject and workload digests, counts, failure codes, and an
    evaluation digest. Do not echo source narratives, artifacts, command
    output, or performance samples from mastery evaluation.
14. Require three independent deterministic passes across at least two commits,
    every score at least 80, a mean of at least 85, and both named drills before
    advancement.

## Consequences

Stage 5 makes the common sources of benchmark self-deception explicit and
machine-checkable. Baseline and candidate receipts can refer to immutable
historical commits within one live JStack session, while artifact files store
only receipt digests and normalized measurements. Audit stays read-only and
cannot silently become the optimization agent.

The local runner is not an OS or network sandbox and retains the current
user's host privileges. Signed evidence cannot prove that the workload is
representative, the host was isolated or idle, the timer was accurate, the
measurements generalize, or production capacity is sufficient. Passing proves
bounded protocol integrity only—not correctness, universal performance,
optimization safety, release readiness, or production authority.
