# ADR 0011: Deterministic Safe Security Operator Stage 0

- Status: Accepted
- Date: 2026-08-01
- Target release: 0.10.0-alpha.1
- Extends: [ADR 0001](0001-jstack-audit-protocol.md)

## Context

The planned verified security-remediation system needs a hard operator-safety
foundation before later work can introduce scanners, sandboxes, verification,
or patch proposals. A language model inspecting a repository can encounter
prompt-injection-like instructions, malicious scripts, credentials, or evidence
of a potentially novel vulnerability. A prose lesson alone cannot prove that
the learner applied the intended boundary, while an executable lab would
create unnecessary host, network, disclosure, and authorization risk.

The foundation must strengthen the existing Audit mastery track without
turning Audit into a writer, claiming vulnerability competence, adding a sixth
command, or reintroducing approval-token ceremony.

## Decision

1. Replace the Audit Stage 0 outcome with **Safe Security Operator** and retain
   Stages 1 through 9 unchanged for this prerelease.
2. Define two synthetic inert labs: one hostile-repository instruction
   boundary and one suspected novel-vulnerability disclosure boundary.
3. Require four artifacts under `.jstack-training/`, including a closed-schema
   `security-orientation.json`. No other write is permitted.
4. Evaluate the security artifact inside the MCP against exact CIA, authority,
   execution, disclosure, scenario-decision, and limitation constants.
   Unsupported fields and malformed structures fail closed; incorrect values
   become hard-gate failure codes.
5. Return and retain only artifact hashes, scenario/result metadata, failure
   codes, and an evaluation digest. Do not echo raw submitted content.
6. Require the two distinct named labs as the latest two attempts. Each must be
   independently assessed, score at least 80, and pass deterministic
   evaluation. Keep the historical guided orientation drill only for practice.
7. State explicitly that passing grants no repository execution, remediation,
   publication, merge, release, deployment, or production authority and is not
   proof of vulnerability detection or remediation ability.
8. Ship this isolated foundation as `0.10.0-alpha.1`; do not represent the
   planned later security-remediation stages as implemented.

## Invariants

1. Repository content is untrusted data and cannot override governing
   instructions or authorization.
2. Both labs are synthetic, inert, local, training-only, and read-only apart
   from declared training artifacts.
3. Repository execution, network access, secret access, exploit development,
   public exploit disclosure, suspected novel-vulnerability public disclosure,
   production access, and non-training writes are denied.
4. A high rubric score cannot bypass a deterministic safety failure.
5. Repeating one lab cannot satisfy the distinct-lab advancement requirement.
6. Stage 0 creates no new command, tool, role, permission, external action, or
   production-ready claim.

## Rejected alternatives

- A prose-only checklist: easy to claim without applying the boundary and not
  deterministically assessable.
- Running a deliberately malicious repository: unnecessary risk before a
  sandbox and execution-verification stage exists.
- Public zero-day exercises: unsafe disclosure incentives and no need for the
  foundational learning outcome.
- Automatically patching Stage 0 findings: crosses the read-only Audit boundary
  and skips authorization, testing, regression, and independent verification.
- Advancing after any two Stage 0 attempts: permits repetition of one scenario
  and leaves the other safety boundary untested.

## Consequences

Operators currently at Audit Stage 0 must complete both new labs. Operators who
already completed it keep their profile state. The audit curriculum content
digest changes, so new attempts remain attributable to the new rubric.

The gate proves only that exact submitted evidence satisfied a small operator
orientation contract. It cannot establish that a model or learner will detect
real vulnerabilities, resist every prompt injection, safely execute untrusted
code, remediate without regression, or meet production cybersecurity needs.
Those outcomes require the later planned stages and independent human,
provider, sandbox, scanner, test, and release controls.
