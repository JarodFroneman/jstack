# ADR 0013: Deterministic Correctness Evidence At Audit Stage 2

- Status: accepted
- Date: 2026-08-03
- Target release: 0.10.0-alpha.3

## Context

Stage 0 established the operator boundary and Stage 1 established an exact-
revision system map. A correctness auditor still needs a way to distinguish a
verified defect from persuasive prose. Free-form findings can silently cite
stale code, omit failure states, invent reproductions, label hypotheses as
blockers, and propose tests that do not protect behavior.

Phase 2 must make logic and reliability evidence falsifiable without turning
the read-only Audit command into a patching agent, arbitrary command runner,
exploit tool, release mechanism, or production authority. Repository execution
also cannot be described as sandboxed when JStack QA provides environment
hardening but no OS or network isolation.

## Decision

1. Keep the existing five commands, 50 canonical MCP tools, Audit read-only
   boundary, mastery profile v3, and token-free host-native action model.
2. Add closed `jstack.audit.correctness-report.v1` and
   `jstack.audit.correctness-reproductions.v1` schemas for the Stage 2 report
   and reproduction manifest.
3. Bind both documents to the current committed Git HEAD and tree, and bind
   the report to the exact manifest digest. Retain the full project fingerprint
   separately to avoid self-reference through the training artifacts.
4. Require exactly four surfaces: logic, state transitions, error handling,
   and reliability. Unsupported coverage, unresolved gaps, or incomplete
   status cannot pass.
5. Require material findings and invariants to cite tracked regular source
   files by bounded line range and current SHA-256.
6. Require every blocker or high/critical claim to be verified,
   high-confidence, reachable or conditional, and linked reciprocally to a
   violated invariant and a reproduction. Reject speculative high severity.
7. Support two reproduction methods. `static-invariant` proves a
   source-visible counterexample without execution. `jstack-qa` must match a
   current passing exact-revision receipt by receipt, discovered command key,
   command fingerprint, profile, and return code.
8. Require every verified finding to have a regression plan covering the
   before-fix failure, after-fix success, unrelated behavior, and failure-state
   behavior.
9. Permit only `correctness-report.json`, `invariants.md`, and
   `reproductions/manifest.json` beneath `.jstack-training/`. Reject raw output
   and extra reproduction files.
10. Return only source-subject metadata, counts, deterministic failure codes,
    and an evaluation digest. Never echo source, report, invariant, or
    reproduction content.
11. Require two consecutive independent attempts scoring at least 80 and
    deterministically passing this contract.
12. Ship the bounded phase as `v0.10.0-alpha.3`; do not represent it as
    semantic completeness, vulnerability absence, zero-day detection, safe
    remediation, release readiness, deployment safety, or production access.

## Consequences

Stage 2 makes correctness claims reviewable and replayable against an immutable
source subject. Strong findings cannot advance on confidence alone, and a
regression plan becomes part of the evidence contract rather than an optional
recommendation. Static proofs provide a safe default; executed reproductions
reuse the existing bounded QA evidence plane.

The evaluator proves structural and revision consistency, not that every
diagnosis is true or every defect was found. The model or reviewer can still
misunderstand business intent. JStack QA is not a sandbox, and this phase does
not patch code. Threat modeling, scanners, adversarial verification,
remediation, isolated patch validation, CI review, and human approval remain
later or separate controls.
