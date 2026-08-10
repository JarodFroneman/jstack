# ADR 0019: Deterministic Enterprise Audit Leadership At Stage 8

- Status: Accepted
- Date: 2026-08-10
- Target release: 0.10.0-alpha.9

## Context

A technically correct finding list is not yet an enterprise release decision.
Engineering leadership also needs proof that the retained result matches the
signed audit, every risk has an accountable disposition, accepted risk has
bounded governance, machine and human reports agree, and a claimed remediation
improves a previously validated baseline without introducing a worse blocker.

Audit remains read-only. It must not silently become the authority that edits
controls, accepts organisational risk, commits code, publishes a report,
releases software, deploys, or accesses production. Stage 8 therefore needs a
closed reconciliation contract rather than an open-ended reporting exercise.

## Decision

1. Add the closed `jstack.audit.enterprise-risk-register.v1` contract. Stage 8
   accepts only `audit-report.md`, `audit-result.json`, `audit.sarif`, and
   `risk-register.json` at their exact `.jstack-training/` paths.
2. Keep `audit-result.json` on the existing `jstack.audit.result.v1` contract
   and `audit.sarif` on SARIF 2.1.0. Do not introduce a second finding truth.
3. Require a fresh current-session audit receipt bound to the exact candidate
   HEAD, release profile, and complete repository scope. Coverage and finding
   digests, counts, active suppression expiries, failure threshold, status, and
   evaluation time must equal the retained result.
4. Permit project-fingerprint drift only when it is fully explained by the four
   exact Stage 8 artifacts written after audit finalization. Any application,
   configuration, Git, or other training-path change fails closed.
5. Require one risk-register entry per current finding, ordered by delivery
   priority before severity. Verified open risk is `remediate`; an unverified
   hypothesis is `investigate`; a finalized suppression is `accepted-risk`.
6. Require owner, meaningful reason, and future target date for open risk.
   Accepted risk must exactly match the finalized fingerprint, scope, owner,
   reason, approval reference, future expiry, compensating control, and
   residual risk. Rejected, stale, malformed, duplicate, wrong-scope,
   future-created, or expired suppressions fail.
7. Regenerate SARIF and the canonical engineering/executive Markdown report in
   the evaluator and require semantic equality. Derive `go` only from a
   complete passing release audit and `no-go` from a complete failing audit.
8. Keep `a8-lead` single-revision. For `a8-controls`, require a separately
   committed candidate whose baseline is a strict ancestor. The baseline
   `audit-result.json` commit and digest must match a prior passed Stage 8
   attempt; reported paths must equal the Git diff; at least one verified
   baseline fingerprint must disappear; the candidate release audit must pass;
   and no introduced blocker, severity increase, or priority escalation may
   remain.
9. Require current passing QA for every discovered command and a current,
   complete, passing security receipt. Report reconciliation does not replace
   correctness or security evidence.
10. Return only subject metadata, counts, digests, decision, regression state,
    failure codes, and an evaluation digest. Passing grants no remediation,
    risk-acceptance, Git, publication, release, deployment, or production
    authority.

## Consequences

Stage 8 can now detect stale or fabricated release reports, receipt/result
drift, omitted or duplicate risks, priority-order manipulation, incomplete
accepted-risk governance, SARIF/Markdown disagreement, unjustified go
decisions, unrelated dirty paths, replayed baselines, unverified remediation,
and severity or priority regressions.

The gate intentionally does not prove vulnerability absence, exploitability,
zero-day detection, standards compliance, universal behavior, legal approval,
risk acceptance, release authorization, deployment safety, or production
safety. Those claims require accountable humans and controls outside this
bounded evidence protocol.
