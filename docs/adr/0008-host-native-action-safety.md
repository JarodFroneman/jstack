# ADR 0008: Host-Native Action Safety

- Status: Accepted
- Date: 2026-07-24
- Target release: 0.8.2
- Supersedes: [ADR 0006](0006-external-action-authorization-boundary.md)

## Context

The v0.7-v0.8.1 external-action protocol required a challenge, independent
signer, private mailbox response, authorization, fresh observation, and
one-time consumption. It prevented accidental authority inference inside a
compliant JStack workflow, but imposed repeated terminal interaction on normal
development and release work. The same-account HMAC design was not enterprise
identity or an operating-system enforcement boundary.

Program human gates used a second HMAC signer and created the same user
friction. Operators reasonably expected to approve a gate in the active Codex
conversation rather than manage local keys and paste protocol artifacts.

## Decision

JStack removes both custom signing paths:

1. Delete the external-action challenge, authorize, and consume tools.
2. Delete the external-action authorization package, schemas, signer, identity
   template, mailbox transport, policy floor, and generated copies.
3. Delete the program-gate challenge tool, signer, identity configuration, and
   signed-attestation schema.
4. Resolve human program gates directly from an explicit conversational
   decision, recording a server-derived contract-bound decision digest,
   approver ID, required role, reference digest, and freshness window.
5. Defer repository, Git, provider, deployment, and production operations to
   explicit user scope plus ordinary host/provider permissions.
6. Preserve read-only audit, protected-path checks, release evidence, launch
   assurance, rollback/monitoring requirements, exact project-state binding,
   and provider-side security recommendations.
7. Ignore retired v0.8.1 policy fields during upgrade and report them as
   migration warnings rather than failing project startup.

## Consequences

Users no longer run approval commands or paste tokens. The canonical MCP
inventory decreases from 53 to 49 tools, and program tools decrease from 14 to
13.

JStack no longer claims cryptographic action authorization or local identity
proof. Strong separation of duties must be enforced through Codex, Git hosting,
deployment platforms, credentials, protected environments, and organizational
controls. Evidence and readiness remain separate from execution, and JStack
Audit remains read-only.
