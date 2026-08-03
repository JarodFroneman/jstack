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

### Audit mastery Stage 0

Audit mastery Stage 0 uses only synthetic inert local scenarios. Repository
instructions are untrusted data and cannot override system, developer, user,
host, policy, or authorization boundaries. Both required labs deny repository
execution, network access, secret access, exploit development, public exploit
or suspected novel-vulnerability disclosure, production access, and writes
outside `.jstack-training/`.

The MCP loads the hashed `security-orientation.json` through descriptor-confined
bounded reads and checks an exact closed-field contract. Malformed or unknown
fields fail closed; wrong values become hard-gate failures. Attempt output
contains evaluation metadata and a digest, not the raw submitted artifact.
Passing is orientation evidence only. It grants no audit execution,
remediation, publication, merge, release, deployment, or production authority.

### Audit mastery Stage 1

Audit mastery Stage 1 treats every repository file and instruction as
untrusted data. Collection is static and read-only: no repository-controlled
code, build, test, analyzer, hook, network operation, credential access, or
production action is permitted. The only repository writes are the declared
`system-map.md`, `trust-boundaries.md`, and `coverage-matrix.json` training
artifacts beneath `.jstack-training/`; any other dirty path hard-blocks the
attempt.

The MCP descriptor-confines and bounds every cited source read. Citations must
name tracked regular files outside `.git` and `.jstack-training`, include valid
line ranges, and match the current SHA-256. The map also binds the exact Git
HEAD and tree, rejects unknown or duplicate fields, caps all collections and
read bytes, validates graph references, requires every evidence record to be
used, and fails closed on unsupported surfaces, unresolved gaps, incomplete
coverage, or unclassified generated-artifact provenance.

Evaluation returns only immutable subject metadata, counts, failure codes, and
a digest; it never returns cited source, map prose, node names, flow data, or
raw artifact content. A pass proves only that the submitted structural map met
the deterministic contract. It is not proof of semantic completeness,
vulnerability absence, zero-day detection, exploitability, remediation
competence, release readiness, deployment safety, or production authority.

### Audit mastery Stage 2

Audit mastery Stage 2 permits only `correctness-report.json`, `invariants.md`,
and `reproductions/manifest.json` beneath `.jstack-training/`; any other dirty
path blocks the attempt. Both closed-schema JSON documents bind the exact Git
HEAD/tree, the report binds the manifest digest, and every cited source range
must resolve to a tracked regular file with a matching current SHA-256.

All four correctness surfaces are mandatory. Blocker and high/critical claims
must be verified, high-confidence, reachable or conditional, and linked to a
violated invariant, a reciprocal reproduction, and a complete regression plan.
Speculative high-severity claims, unresolved gaps, unused evidence, stale
bindings, malformed or secret-like values, fabricated QA receipts, and raw
reproduction files fail closed.

Static invariant cases do not execute repository code. Executed cases require
a current passing `jstack_qa` receipt whose command key, command fingerprint,
profile, and return code exactly match the manifest. JStack QA's scrubbed
environment and isolated HOME do not provide OS or network isolation; execute
untrusted code only in an externally enforced container or VM. Evaluation
returns metadata and digests, not raw source, report, or reproduction content.
Passing Stage 2 grants no remediation, Git, release, deployment, or production
authority.

## Launch-Assurance Safety

The v2 launch catalog is declarative, versioned, and selected from an explicit
surface profile plus a non-lowerable risk tier. Assessment requires a clean
committed subject and binds Git, base, policy, catalog, selection, risk,
deployment fingerprint, static surface-hint digest, reconciliation digest,
target, environment, tool version, and server session. Static detection is
bounded and returns only paths and marker labels. It cannot discover every
legal, merchant, jurisdictional, or production fact, so the accountable
declaration remains required.

Evidence registration accepts only bounded structured JSON in the project or
`~/.jstack/evidence`, rejects symlinks, uses stable file-identity hashing, and
returns no content. The evaluator derives status from exact required
assertions, observations, completeness, truncation, producer, independence,
and target metadata. Caller-written outcomes, verifier prose, summaries,
READMEs, and arbitrary files cannot satisfy a control.

Provider-neutral scanner JSON and SARIF are normalized by the read-only Audit
subsystem without executing a scanner or uploading code. Wrong targets,
missing scope, unsafe size, malformed metadata, truncation, non-independent
producers, and unresolved high or critical findings fail closed. A scanner
still cannot prove its ruleset covered every weakness or replace a
penetration test. Critical risk therefore requires a distinct independent
human security-review artifact.

Receipts prove contract binding, artifact identity at collection, freshness,
and JStack's derived result. They do not prove producer honesty, legal
sufficiency, provider state beyond the artifact, or facts outside scope.
Blockers cannot be waived. High/critical security controls cannot be waived,
and critical risk permits no waiver. Other eligible waiver records require an
external reference, owner, bounded expiry, compensating control, and residual
risk; policy can disable them.

Launch tools make no network request or production change. Live payment,
webhook, email, DNS, search, analytics, browser, and device exercises require a
separately authorized safe workflow. A launch receipt never authorizes a charge,
commit, push, pull request, merge, tag, release, deployment, or production
mutation.

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

A loop completion receipt does not execute repository, Git, provider,
deployment, production, secret-access, policy, or destructive operations.
Those actions remain governed by the user's explicit scope and the host and
provider's normal permissions.

## Host-Native Action Safety

Current JStack releases have no custom action-approval challenge, signer, token, mailbox,
authorization receipt, consumption step, or terminal command. The MCP remains
an evidence and orchestration control plane; it does not perform GitHub,
deployment, or production operations itself.

The accountable Lead resolves exact targets, checks current state, stays within
the user's request, and follows any ordinary Codex or provider approval UI.
JStack readiness, audit, gate, handoff, and completion receipts are evidence;
they do not automatically execute an operation or widen task scope.

Use branch protection, protected environments, least-privilege credentials,
provider-side review rules, host tool allowlists, and OS/container isolation
where stronger enforcement is required. JStack cannot intercept a separate
process that directly invokes Git, a provider API, CI/CD, or production tools.

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

Human gates record an explicit decision from the active conversation with an
approver ID, required role, decision, reference digest, contract/gate binding,
and freshness window. This is an auditable caller-supplied record, not
cryptographic identity proof, enterprise SSO, legal non-repudiation, or proof
of physical presence. The Lead must never invent a decision or treat silence
as approval.

External evidence and phase outputs are bounded regular files, confined to the
project or `~/.jstack/evidence`, hashed without following the final symlink
where supported, and freshness checked. JStack stores metadata and hashes, not
the authoritative artifact. Stale, changed, missing, oversized, timed-out, or
contract-mismatched evidence cannot satisfy a gate.

Program completion revalidates durable child attestations, output hashes,
baseline ancestry, policy, tool version, final gates, and current final
evidence. A program receipt has the same non-authorization boundary as a loop
receipt.
