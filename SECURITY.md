# Security Policy

## Supported Version

Security fixes are applied to the latest release on the default branch.

## Reporting

Do not open a public issue containing a credential, exploit payload, or private
repository detail. Use GitHub's private vulnerability reporting for this
repository. Revoke any exposed credential before reporting it.

Include the affected version, operating system, reproduction, impact, and any
suggested mitigation. Reports are acknowledged after they are reviewed; no
response-time guarantee is offered.

## Trust Boundary

JStack is a local workflow and evidence tool. Its QA runner executes reviewed
repository commands with a scrubbed environment and isolated home, but standard
Python cannot remove the current user's filesystem or network privileges. Use a
host/container sandbox for untrusted repositories.

Evidence receipts protect against accidental or MCP-caller alteration inside
one server session. They do not protect against compromise of the same operating
system account.

## Audit Safety

Default static audit collection is read-only, performs no network operation,
uses descriptor-confined repository reads, is bounded by file/output limits,
and accepts no arbitrary commands or executable paths. Curated analyzer
execution is a separate trusted-code boundary: it requires exact approval bound
to the adapter, revision, workspace fingerprint, policy, and launcher identity,
but still has the current user's host filesystem and network privileges.
Offline environment flags are requests, not a firewall. Run untrusted analyzers
or any check needing enforced isolation in a read-only container or VM with its
network disabled.

Caller-provided finding text containing a recognized secret pattern is rejected;
defense-in-depth rendering also redacts recognized provider and assignment
formats. Arbitrary unlabelled strings cannot be proven non-secret, so callers
must submit only classifications and locations, never values. Suppressions
require an exact finding fingerprint, bounded scope, owner, reason, approval
reference, creation and expiry dates, compensating control, and residual risk.
Expired or source-stale suppressions do not apply; expiry is evaluated against
server time and rechecked when release readiness consumes the receipt.

The original `jstack_security_audit` remains a bounded heuristic credential
scan. A broad audit result never replaces its security receipt.
