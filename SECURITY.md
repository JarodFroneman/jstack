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

## Specialist Capability Safety

The capability catalog is declarative and permission-neutral. Every entry must
use `permissionMode: inherit-role`; a capability cannot add an agent, grant a
tool, turn a read-only role into a writer, widen file ownership, weaken policy,
or authorize a protected action. Unknown or unauthorized explicit capability
IDs and catalog validation errors fail closed.

Specialist results are accepted only as bounded structured data. Result
receipts bind the exact goal digest, team, role, capabilities, catalog and
selection digests, Git state, policy, JStack version, result, telemetry, and
server session. Handoff validation rejects missing or duplicate roles,
tampering, staleness, write-scope violations, failed results, and unresolved
contradictions. These HMAC receipts protect against accidental or caller-side
alteration during one server session; they do not prove that model-authored
claims are true or defend against compromise of the same operating-system
account.

Specialist telemetry is intentionally minimized. It permits bounded IDs,
timestamps, status, tool names/statuses, evidence references, derived digests,
and optional counts. `rawContentStored` must be false. Prompts, messages, tool
arguments, model output, hidden reasoning, and arbitrary logs have no schema
fields; recognized raw-content keys and secret-like values are rejected.
Callers must not disguise raw content as metadata. Metadata can still reveal
activity patterns or project structure, so protect it as local operational
evidence.

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

The loop's capability contract is part of readiness, durable state, material
revision, and completion binding. Smart-subagent and full-team checkpoints and
finalization require a current specialist handoff receipt. This requirement
does not make agent execution sandboxed and does not extend loop autonomy.

Loop mastery Stage 9 uses a separate assessor HMAC key from
`JSTACK_LOOP_ASSESSOR_HMAC_KEY`. Keep it outside the repository. It signs the
exact capstone evaluation, artifact set, Git state, rubric, and unseen
challenge; it is not a runtime authorization credential.

A loop completion receipt is not permission to create a repository, change a
remote, commit, push, create a pull request, merge, tag, release, deploy, alter
production, read secrets, weaken policy, or perform destructive Git operations.
The first eleven actions each require their own exact signed and consumed v0.7
external-action permit; project/user approval prose is not a substitute.

## External-Action Safety

The external-action protocol binds one action to exact provider, repository,
visibility, URL, refs, full commit, environment, current Git/workspace/policy
state, branch, remote snapshot, tool version, and MCP session. A configured
role holder signs the canonical challenge outside Codex. Authorization and
one-time consumption repeat state checks, require a fresh exact provider
observation, and return a permit valid for at most 60 seconds. Expiry, replay,
retry, mismatch, state drift, or action escalation fails closed.

Private challenge and consumption state under `~/.jstack/external-actions` is
permission-restricted and session-sealed. Same-session memory rejects replay
after local state rollback; restarting the MCP invalidates every receipt. This
protects compliant JStack workflows from accidental inference and caller-side
tampering, not from compromise of the same OS account.

The MCP never performs the protected operation and cannot intercept a separate
process that directly invokes Git, a provider API, CI/CD, or production tools.
Use provider branch protection, environment approvals, least-privilege
credentials, host tool allowlists, and OS/container isolation for a boundary
that must withstand a malicious or non-compliant executor.

## Program Safety

Program state is stored under `~/.jstack/programs/` with the same private,
atomic, hash-bound persistence model as loop state. A program coordinates
bounded child loops but executes no caller-defined command and grants no new
filesystem, subagent, deployment, or release authority.

Every mutating program call requires a durable idempotency key. Exact retries
return current state; reuse for another action or payload fails closed. The
event chain, contract history, snapshot, operation records, and pending
transaction are mutually bound. One non-terminal program owns a repository's
orchestration slot.

Parallel phases require explicit declarations, linked worktrees from the same
Git common directory, disjoint top-level scopes, and policy capacity. This is a
conservative conflict check, not proof that changes are semantically mergeable.

Human gates currently use the `signed-local` provider. Identity configuration
contains role and key-environment bindings; keys must remain outside Git and
MCP arguments. The operator signer validates and signs an exact challenge
outside Codex. HMAC proves possession of the shared local key, not enterprise
SSO, non-repudiation, physical presence, or safety from compromise of the same
OS account. Codex must not run the signer for the approver.

External evidence and phase outputs are bounded regular files, confined to the
project or `~/.jstack/evidence`, hashed without following the final symlink
where supported, and freshness checked. JStack stores metadata and hashes, not
the authoritative artifact. Stale, changed, missing, oversized, timed-out, or
contract-mismatched evidence cannot satisfy a gate.

Program completion revalidates durable child attestations, output hashes,
baseline ancestry, policy, tool version, final gates, and current final
evidence. A program receipt has the same non-authorization boundary as a loop
receipt.
