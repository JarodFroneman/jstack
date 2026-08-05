# ADR 0015: Deterministic Architecture Evidence At Audit Stage 4

- Status: Accepted
- Date: 2026-08-05
- Target release: 0.10.0-alpha.5

## Context

Audit mastery Stages 0 through 3 established safe operation, repository
mapping, correctness evidence, and static threat modelling. Stage 4 must teach
architecture and maintainability judgment without treating taste as evidence,
running untrusted repository code, or allowing the read-only Audit workflow to
make a remediation.

Free-form architecture reviews commonly cite the current worktree rather than
an immutable revision, label stylistic preferences as defects, estimate change
cost without tracing affected components, omit contracts and compatibility,
or claim a refactor is behavior-preserving without an exact diff or test
receipt. A deterministic contract can validate subject binding, graph
integrity, traceability, and verification evidence while leaving semantic
architecture judgment to the auditor and reviewer.

## Decision

1. Ship Audit Stage 4 as `jstack.audit.maintainability-report.v1` with one
   closed JSON schema and two hash-bound narrative artifacts.
2. Permit only `.jstack-training/architecture-map.md`,
   `.jstack-training/maintainability-report.json`, and
   `.jstack-training/migration-outline.md` to be dirty during an attempt.
3. Bind exact baseline and candidate Git commits and trees. Read cited source
   only from those immutable Git objects, with revision labels, bounded line
   ranges, and exact SHA-256 hashes.
4. Require exactly six coverage surfaces: module boundaries, dependency
   direction, contracts and compatibility, change amplification, testability,
   and migration risk. Unsupported coverage, a gap, or incomplete status is a
   no-go.
5. Require cited components, dependencies, contracts, change scenarios,
   findings, remediations, and compatibility assessments with unique, used,
   internally valid references.
6. Require every change scenario's touch-point count to equal its exact
   affected-component set. Require every material finding to link dependency,
   contract, and change-scenario evidence. Reject style-only findings.
7. Keep `a4-architecture` static: baseline equals candidate, findings remain
   open, remediations remain proposed, and QA bindings are forbidden.
8. Keep remediation authority outside Audit. For `a4-remediation`, accept only
   evidence about a candidate already changed and committed through a separate
   authorized development workflow.
9. Require the implementation baseline to be a strict ancestor, the reported
   changed paths to equal the exact Git diff, exactly one resolved finding to
   have exactly one implemented-and-verified reciprocal remediation, and every
   contract to have baseline/candidate compatibility evidence.
10. Reject breaking or unsupported compatibility. Require the implementation
    QA binding to match a current passing exact-candidate `jstack_qa` receipt by
    receipt, command identity, fingerprint, profile, and return code.
11. Treat repository content as untrusted data. The evaluator executes no
    repository code, uses no network or secrets, writes no application code,
    and grants no Git, publication, release, deployment, or production
    authority.
12. Return only immutable subject metadata, counts, failure codes, and an
    evaluation digest. Do not echo source, paths, findings, root causes, or
    narrative content into the attempt result.
13. Require three independent deterministic passes across at least two commits,
    every score at least 80, a mean of at least 85, and both named drills before
    advancement.

## Consequences

Stage 4 evidence becomes revision-aware, reviewable, and fail-closed. It
separates architecture diagnosis from implementation authority and makes
change-amplification, compatibility, exact-diff, and QA claims independently
checkable.

The evaluator cannot establish that a model-authored architecture diagnosis is
semantically correct, that every structural risk was found, or that passing
tests prove behavior preservation. It cannot observe deployed infrastructure
or provider state. Passing therefore proves protocol and evidence integrity
only—not maintainability, compatibility, vulnerability absence, remediation
safety, release readiness, or production security.
