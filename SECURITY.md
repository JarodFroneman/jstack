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

## Loop Safety

Loop state is stored under `~/.jstack/loops/` with private directories and
atomic files. Contract revisions, the current snapshot, and events are SHA-256
bound, and one write-capable loop holds the local Git-checkout lease. These
controls detect accidental or caller-side state alteration; they are not
protection from a compromised operating-system account or a distributed lock
across machines. Separately linked worktrees have independent leases.

The loop MCP tools execute no arbitrary caller commands. QA and approved audit
adapters retain their existing trust boundaries. Scope violations, policy
changes, unapproved protected paths, stale receipts, repeated failures,
stagnation, and oscillation fail closed or require approval. Exact baseline
ancestry, segment-aware path identity, and hidden-index checks prevent Git state
from silently broadening scope. L3 is limited to explicitly approved low-risk
work in a linked Git worktree.

Goal-readiness receipts are HMAC-signed, short-lived, and server-session local.
They bind the normalized semantic contract and context to the current Git
fingerprint, policy, tool version, and revision base. Repository context sources
must remain inside the Git root and cannot be symlinks. The receipt prevents a
caller from silently changing the assessed target; it does not prove user
statements, external sources, or model inferences are true.

Loop mastery Stage 9 uses a separate assessor HMAC key from
`JSTACK_LOOP_ASSESSOR_HMAC_KEY`. Keep it outside the repository. It signs the
exact capstone evaluation, artifact set, Git state, rubric, and unseen
challenge; it is not a runtime authorization credential.

A loop completion receipt is not permission to commit, push, deploy, release,
read secrets, weaken policy, or perform destructive Git operations. Those
actions continue to require their existing project and user approvals.
