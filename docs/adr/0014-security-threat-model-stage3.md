# ADR 0014: Deterministic Static Threat Models At Audit Stage 3

- Status: Accepted
- Date: 2026-08-05
- Target release: 0.10.0-alpha.4

## Context

Audit mastery Stages 0 through 2 established safe operation, exact-revision
repository mapping, and correctness evidence. Stage 3 must teach security and
threat-modelling judgment without turning a mastery record into a penetration
test, vulnerability-free claim, remediation permit, or production authority.

Free-form threat-model prose is difficult to verify. It can omit threat
classes, cite stale code, invent attack reachability, confuse authentication
with authorization, inflate hypotheses into blockers, use outdated standards,
or retain sensitive payloads. A deterministic contract can validate structure,
binding, traceability, and safety, while semantic security judgment remains the
auditor's and independent assessor's responsibility.

The design follows the methodology-neutral
[OWASP Threat Modeling Project](https://owasp.org/www-project-threat-modeling/)
Four Question framework and uses STRIDE as a complete classification aid. Its
pinned mapping registry uses official releases of
[OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/),
[OWASP Top 10:2025](https://owasp.org/Top10/2025/),
[MITRE CWE 4.20](https://cwe.mitre.org/data/archive.html), and
[NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

## Decision

1. Ship Audit Stage 3 as `jstack.audit.security-findings.v1` with one closed
   JSON schema and two hash-bound narrative artifacts.
2. Permit only `.jstack-training/threat-model.md`,
   `.jstack-training/security-findings.json`, and
   `.jstack-training/abuse-cases.md` to be dirty during an attempt.
3. Bind the report to the current committed Git HEAD/tree. Cite only current
   tracked regular source files outside `.git` and `.jstack-training`, with
   bounded line ranges and exact SHA-256 hashes.
4. Require the OWASP Four Question framework and exactly six STRIDE coverage
   records. `unsupported`, an unresolved gap, or incomplete status is a no-go.
5. Require source-backed assets and CIA objectives, bounded adversaries, trust
   boundaries and data flows, observed controls, abuse cases, attack paths,
   findings, and standards mappings.
6. Enforce unique and used IDs, known references, abuse-case/attack-path
   reciprocity, and finding/standards-mapping reciprocity.
7. Require every blocker to be high or critical, high-confidence, verified,
   and linked to at least one verified reachable path with source, sink,
   preconditions, impact, crossed boundaries, and mitigating-control review.
8. Require at least one critical blocker in the seeded Stage 3 drill. Reject
   high or critical hypotheses rather than silently treating them as verified.
9. Accept applicable mappings only from the pinned registry: MITRE CWE 4.20,
   NIST SP 800-218 v1.1, OWASP ASVS 5.0.0, and OWASP Top 10:2025. Validate each
   standard's version and identifier form.
10. Validate both narrative artifacts as bounded, non-empty UTF-8 with stable
    hashes. Reject recognized secret-like values in JSON and narratives.
11. Keep Stage 3 static-only. Prohibit repository execution, live
    exploitation, retained exploit payloads, network authority, secret access,
    remediation, unsafe public disclosure, release, deployment, and production
    action.
12. Exempt this static-only package from the generic Stage 2+ QA-receipt rule.
    Dynamic adversarial verification remains a later, separately bounded
    mastery stage.
13. Return only immutable subject metadata, counts, failure codes, and an
    evaluation digest. Do not echo source, findings, paths, or narrative
    content into the attempt result.
14. Require two consecutive independent attempts scoring at least 80 and
    passing the deterministic evaluator before advancement.

## Consequences

Stage 3 evidence becomes reviewable, versioned, and fail-closed without
granting dangerous authority. The contract materially reduces stale citations,
dangling models, speculative blockers, standards drift, and accidental secret
retention.

The evaluator cannot know that every real vulnerability or seeded defect was
found, that every semantic claim is correct, or that an identified path works
against a deployed service. It cannot observe infrastructure or provider state
absent from the repository. Passing therefore proves protocol and evidence
integrity only—not vulnerability absence, exploitability, zero-day detection,
compliance, remediation safety, release readiness, or production security.
