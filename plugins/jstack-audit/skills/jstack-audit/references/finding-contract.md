# Finding Contract

## Required Fields

Use schema `jstack.audit.finding.v1`. Supply `ruleId`, `domain`, `title`,
`severity`, `confidence`, `priority`, `verificationState`, `status`, location,
claim, evidence, failure path, preconditions, impact, likelihood, standards,
structured remediation (recommended change, alternatives, and trade-offs),
verification plan, residual risk, and suppression metadata. Retain an optional
source symbol when the repository evidence provides one.

The finalizer generates the stable `findingId` and `fingerprint`; never invent
or override them.

## Evidence Classes

- `test-reproduced`: a retained deterministic test demonstrates the defect.
- `tool-confirmed`: a supported deterministic analyser confirms it.
- `source-proven`: cited source and contract establish the defect directly.
- `reasoned-strong-evidence`: reachability and controls are well supported but
  no deterministic reproduction is available.
- `unverified-hypothesis`: plausible but not adequately proven; cannot block.

## Scoring

Severity is technical/business consequence if true. Confidence is evidence
strength. Priority is action order after exposure and controls. Use CVSS 4.0
only for genuine security vulnerabilities; never use it for correctness,
architecture, maintainability, or performance findings.

## Challenge Checklist

Before retaining a material finding:

1. Trace the real caller and reachable input.
2. Check guards, authorization, validation, transactions, retries, and tests.
3. Identify required preconditions and affected asset or invariant.
4. Look for generated/source-copy ownership and compatibility constraints.
5. Attempt a bounded reproduction when approved and safe.
6. Remove, downgrade, or mark uncertain when contrary evidence wins.

## Suppressions

Require exact fingerprint and scope, owner, reason, approval reference,
creation date, future expiry, compensating control, and residual risk. Reject
blanket, permanent, expired, malformed, or content-stale records.
