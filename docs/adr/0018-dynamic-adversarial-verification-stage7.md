# ADR 0018: Signed Dynamic And Adversarial Evidence At Audit Stage 7

- Status: Accepted
- Date: 2026-08-09
- Target release: 0.10.0-alpha.8

## Context

Static review can identify a plausible defect without proving that the stated
preconditions, boundary behavior, or mitigating controls produce the claimed
outcome. Conversely, an existing test suite can pass while omitting negative
inputs, state transitions, fault paths, authorization boundaries, or resource
limits. Audit Stage 7 needs to challenge hypotheses with dynamic evidence
without quietly turning a read-only audit into an execution, exploit,
remediation, or production agent.

OWASP's Web Security Testing Guide describes testing as active assessment,
requires consistent and reproducible methods, and treats negative requirements
as testable security properties. OWASP ASVS 5.0 provides a current application-
security verification baseline, while NIST SP 800-218 recommends integrating
secure practices throughout the software lifecycle. These sources support a
repeatable verification gate; they do not make one bounded local run a claim of
security completeness.

- [OWASP Web Security Testing Guide: Introduction and Objectives](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/00-Introduction_and_Objectives/)
- [OWASP Web Security Testing Guide: Stable Introduction](https://owasp.org/www-project-web-security-testing-guide/stable/2-Introduction/README)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-218 Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)

## Decision

1. Add the closed `jstack.adversarial.capture.v1` protocol. A capture contains
   only a campaign ID and digests, deterministic seed, input-corpus and target-
   scope digests, and bounded cases. Every case has an ID, one closed category,
   hypothesis ID, input and expectation digests, and exactly two classified
   runs. Raw inputs, payloads, source, secrets, stdout, and stderr are not part
   of the protocol.
2. Require at least four cases across at least three categories. Each case's
   two runs must have identical `confirmed` or `refuted` status and identical
   outcome digests. Each run may report only `none-observed` for external
   effects. That value is an observation, not proof that effects were blocked.
3. Add `jstack_adversarial_capture`. Discovery is read-only. Execution accepts
   only one discovered command and requires an exact reviewed revision,
   project fingerprint, and policy digest inside a separately authorized
   trusted development or QA workflow. The user does not paste a token,
   signing command, or confirmation digest.
4. Run the capture command with closed stdin, a scrubbed environment, isolated
   HOME, process-group timeout handling, and output limits. Record
   `networkIsolationEnforced=false`. This profile is not an OS or network
   sandbox and retains the current user's filesystem and network privileges.
5. Sign a session-local receipt over the exact Git commit/tree, current policy,
   command/fingerprint, campaign, plan, deterministic corpus and seed, target
   scope, environment, normalized capture, case-set digest, and outcome-set
   digest. Receipt verification against a historical baseline uses immutable
   Git identity and the current server session, never caller-authored summary
   claims.
6. Add the closed `jstack.audit.adversarial-verification.v1` result contract.
   It binds baseline/candidate revisions, campaign, captures, all eight category
   classifications, hash-verified source evidence, hypotheses, reciprocal
   false-positive assessments, harness comparison, QA, security, gaps,
   limitations, and the three exact training artifacts.
7. Require every candidate case to belong to exactly one hypothesis. The set
   must include static-finding and dynamic-observation origins, at least one
   confirmed dynamic observation, and both confirmed and refuted dispositions.
   Every hypothesis gets exactly one `supported` or `false-positive`
   assessment consistent with its case outcomes.
8. Require current passing QA receipts for every discovered command and a
   current complete passing security receipt. Dynamic evidence never replaces
   correctness or security gates.
9. Keep `a7-adversarial` single-revision and non-mutating. Keep
   `a7-harness` verification-only: its candidate must already be committed by a
   separate workflow, its baseline must be a strict ancestor, changed paths
   must equal the Git diff, at least one case must be added, no case may be
   removed, and every shared contract and outcome must remain stable.
10. Return only subject metadata, counts, digests, and failure codes from the
    evaluator. Passing grants no exploit, remediation, harness, Git,
    publication, release, deployment, or production authority.

## Consequences

Stage 7 now detects fabricated summaries, nondeterministic cases, omitted
category classification, unowned cases, incomplete false-positive analysis,
stale or mismatched receipts, missing QA/security evidence, hidden case
removals, and unrelated implementation diffs. It can represent refuted static
findings and newly confirmed dynamic observations without forcing either into a
preselected conclusion.

The new gate intentionally does not prove vulnerability absence,
exploitability, zero-day detection, universal behavior, target authorization,
host or network isolation, production safety, or release readiness. Untrusted
repositories and active security tests require an externally enforced
container or VM, explicit target authorization, and controls outside JStack's
standard-library local runner.
