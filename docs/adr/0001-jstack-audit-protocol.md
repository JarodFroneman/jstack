# ADR 0001: Evidence-Bound JStack Audit Protocol

- Status: Accepted for proposed 0.3.0
- Date: 2026-07-13

## Context

JStack 0.2.1 has three delivery workflows, deterministic project/policy
inspection, explicitly approved QA execution, a bounded credential scanner, and
session-local QA/security receipts. A broad repository audit needs semantic
agent reasoning, but release evidence must remain deterministic, scoped, and
fail closed.

Expanding `jstack_security_audit` would silently change the meaning of a receipt
already consumed by release readiness. A one-step broad audit would also blur
candidate reasoning, evidence validation, and final result calculation.

## Decision

Add `/jstack-audit` as a fourth, read-only workflow backed by two MCP operations:

- `jstack_audit` binds repository state, baseline, policy, controls, scope,
  profile, adapter inventory, and inspected-input manifest into a signed audit
  session and coverage contract.
- `jstack_audit_finalize` validates current state, structured findings,
  coverage, paths, suppressions, and accepted risk; then derives the result and
  issues a separate `kind="audit"` receipt for eligible Git projects.

The agent performs candidate generation and an explicit challenge pass. The MCP
does not perform model reasoning and does not attest semantic truth. Audit
result and finding contracts are versioned. SARIF 2.1.0 uses stable partial
fingerprints.

Profiles are `quick`, `standard`, `deep`, and `release`. Required evidence is
fixed before review. Missing mandatory evidence yields `incomplete`, never
`pass`.

The audit core is a standard-library package under `mcp/jstack/audit/`. Static
collection is read-only and performs no network work, uses canonical
repository-relative paths, rejects traversal/symlinks/races, and enforces
resource limits and redaction. Curated analyzer execution is separately
approved trusted-code execution; local offline flags are not a sandbox or
firewall.

The existing credential scanner, its security receipt, and existing release
gate remain unchanged. Audit release enforcement is opt-in through
`audit.releaseRequiresAuditReceipt`.

Artifact-only roots may receive advisory evidence reports but cannot receive a
Git-bound audit receipt or formal release-ready decision.

Add a separate audit mastery curriculum. Migrate local mastery profiles from v1
to track-aware v2 atomically, retaining existing data under engineering and
keeping engineering as the default when no track is supplied.

## Consequences

Positive consequences:

- semantic review stays flexible while evidence binding stays deterministic;
- security receipt compatibility is preserved;
- stale state, incomplete coverage, malformed findings, and unsafe
  suppressions fail closed;
- audit outputs can interoperate through stable JSON and SARIF;
- engineering and audit training progress independently.

Costs and limitations:

- receipts are process/session local and do not resist compromise of the same
  OS account;
- semantic findings remain advisory claims requiring human judgment;
- the Python process model is not an OS sandbox;
- dedicated plugins still require the shared JStack MCP installation;
- portable top-level slash-palette discovery must be verified in each Codex
  client; `$jstack-audit` is the umbrella/legacy fallback and
  `$jstack-audit:jstack-audit` is the dedicated-plugin fallback.

## Rejected Alternatives

- Replace `jstack_security_audit`: rejected because it breaks receipt and
  release compatibility.
- Let the MCP generate semantic findings: rejected because the deterministic
  server has no model boundary and must not fabricate reasoning.
- Accept arbitrary scanner commands: rejected because repository-controlled
  execution would violate the audit trust model.
- Require audit receipts for every existing release immediately: rejected for
  backward compatibility; the first release uses an opt-in gate.
- Treat artifact hashes as release certification: rejected because artifact-
  only roots lack the Git-bound evidence contract.
