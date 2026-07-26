# ADR 0009: Risk-Tiered Launch Assurance v2

- Status: Accepted
- Date: 2026-07-26
- Target release: 0.9.0
- Supersedes the evidence model in:
  [ADR 0007](0007-launch-assurance-protocol.md)

## Context

Launch Assurance v1 made a reviewed 37-point checklist conditional and bound
its receipts to a clean Git candidate. Its evidence registration still trusted
the caller to supply `pass`, a verifier name, and a prose summary for one
artifact per control. A README or configuration snapshot could therefore be
registered as a passing claim without machine-checkable proof that all
necessary subconditions had been examined.

The expanded pre-launch review identified material gaps: authorization needed
negative tenant probes, rate limits did not prove cost caps, CORS did not prove
CSRF protection, legal links did not prove data governance, dependency
presence did not prove license disposition, and an unspecified “security scan”
did not prove completeness, target identity, independence, or resolution of
high-severity findings.

## Decision

1. Replace the active catalog with a deterministic 47-control v2 catalog across
   22 explicit surfaces and four risk tiers.
2. Derive a non-lowerable risk floor from declared surfaces and enterprise
   policy. High-risk security controls become blockers; critical required
   controls become blockers.
3. Run bounded static surface-hint detection. A detected but omitted surface
   requires an accountable, evidence-referenced `not-applicable`
   reconciliation before a session is issued.
4. Bind every session and receipt to an immutable SHA-256 deployment
   fingerprint in addition to Git, environment, policy, catalog, and surface
   state.
5. Replace caller-supplied outcomes with structured assertion evaluation.
   Accept only native v2 JSON, provider-neutral scanner JSON, or bounded SARIF
   2.1.0.
6. Give each control one or more risk-active evidence requirements with exact
   assertion, observation, producer-count, independence, and format
   constraints.
7. Normalize external scanner output in the read-only Audit subsystem. Reject
   wrong targets, missing scope, incomplete/truncated results, non-independent
   producers, and unresolved high/critical findings.
8. Require independent scanner evidence at high risk. At critical risk require
   both the scanner and a distinct independent human security review.
9. Forbid waivers for high/critical security controls and all critical-risk
   controls.
10. Preserve the existing five commands and the host-native no-token action
    model.

## Consequences

Launch integrations must produce structured artifacts and register each active
requirement. v1 session and receipt tokens cannot satisfy v2 gates. More
high-risk launches will stop as incomplete until scanners, negative tests,
operational controls, and accountable human evidence exist.

The stronger protocol still cannot prove producer honesty, complete scanner
coverage, legal sufficiency, or facts beyond the observed scope. It provides a
tamper-evident, exact-target record of what JStack evaluated; organizational
identity, separation of duties, sandboxing, provider protections, and human
judgment remain outside its local HMAC boundary.
