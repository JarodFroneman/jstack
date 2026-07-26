# Host-Native Action Safety

JStack v0.8.2 removes its custom approval subsystem. Users are never asked to
generate or paste an approval token, run an approval command in a terminal,
manage a signing key, or move a challenge response between Codex and the MCP.

## The User Experience

For ordinary development, the user states the outcome in Codex and JStack
plans, builds, reviews, tests, audits, and reports evidence. When an in-scope
repository, Git, provider, deployment, or production action is needed, the
accountable Lead uses the host or provider normally.

JStack adds none of the following:

- an approval challenge file;
- an HMAC identity configuration;
- an approval mailbox;
- a signed token;
- an authorize or consume call;
- an `APPROVE ONCE` prompt; or
- a terminal command for the user.

Codex or a provider may still show its own ordinary safety or authentication
UI. That is part of the host/provider, not a JStack protocol.

## Safety Contract

Removing the custom ceremony does not remove engineering boundaries:

- Stay within the user's explicit request and the active task scope.
- Resolve the exact repository, remote, branch, tag, environment, and
  operation before irreversible work.
- Re-check current state before destructive or production-impacting actions.
- Do not infer permission for a materially different action.
- Respect Codex permissions, provider authentication, branch protection,
  protected environments, and organizational review rules.
- Keep JStack Audit strictly read-only.
- Treat QA, security, launch, release-readiness, handoff, loop, and program
  receipts as evidence, not automatic execution.

JStack's MCP does not perform GitHub, deployment, or production operations.
Those remain host/provider operations.

## Human Program Gates

Program gates no longer use a signer or token. The Lead shows the exact gate in
the active conversation and waits for an explicit decision. The
`jstack_program_gate_resolve` tool records:

- the current program and gate digest;
- the named approver ID;
- one role required by the gate;
- `approved` or `rejected`;
- a digest of the bounded non-secret reference;
- server issue and expiry times; and
- a decision-record digest.

This record supports role coverage, quorum, freshness, invalidation, and
auditing. It is caller-supplied evidence and does not claim SSO,
non-repudiation, or cryptographic identity proof. Silence is never approval.

## Stronger Organizational Enforcement

Teams that require separation of duties should use provider-side controls:
branch protection, required reviews, protected environments, least-privilege
credentials, deployment approvals, audit logs, and hardened execution hosts.
JStack does not replace those controls and cannot intercept a separate process
running under the same operating-system account.

See [SECURITY.md](../SECURITY.md), [ADR 0008](adr/0008-host-native-action-safety.md),
and the [v0.8.2 migration guide](migration-0.8.2.md).
