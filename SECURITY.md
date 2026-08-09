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

JStack is a local workflow and evidence tool. Its QA/performance runner executes reviewed
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

### Audit mastery Stage 3

Audit mastery Stage 3 permits only `threat-model.md`,
`security-findings.json`, and `abuse-cases.md` at their exact
`.jstack-training/` paths. Any other dirty path blocks the attempt. The closed
JSON contract binds the exact Git HEAD/tree and both narrative hashes. Every
source citation is descriptor-confined, bounded, outside `.git` and
`.jstack-training`, tracked as a regular file, and verified against its current
SHA-256.

The assessment is static and treats repository content as untrusted data. It
does not execute repository code, probe live targets, access the network or
secrets, retain exploit payloads, remediate, publish, release, deploy, or touch
production. The two narratives must be non-empty UTF-8 and are rejected with
the structured report if recognized secret-like values are present.

Complete STRIDE classification is mandatory. Every asset, adversary, trust
boundary, control, abuse case, attack path, finding, and standards mapping must
be cited, internally valid, and used. Abuse cases and attack paths, plus
findings and mappings, must be reciprocal. Blockers require verified reachable
paths and may not be speculative; the seeded drill requires a critical
blocker. Standards identifiers are pinned to MITRE CWE 4.20, NIST SP 800-218
v1.1, OWASP ASVS 5.0.0, or OWASP Top 10:2025.

Evaluation returns only metadata, counts, failure codes, and a digest. Passing
Stage 3 proves that the submitted package met the deterministic evidence
contract. It does not prove vulnerability absence, exploitability, zero-day
detection, semantic correctness of model-authored findings, standards
compliance, remediation safety, release readiness, or production security.

### Audit mastery Stage 4

Audit mastery Stage 4 permits only `architecture-map.md`,
`maintainability-report.json`, and `migration-outline.md` at their exact
`.jstack-training/` paths. The closed JSON contract binds exact baseline and
candidate Git commits and trees, hash-binds both narratives, and restricts
evidence to bounded tracked source lines read from those immutable Git
objects. Recognized secret-like JSON or narrative values are rejected.

The evaluator treats repository content as untrusted data. It does not execute
repository code, access the network or secrets, edit application code, mutate
Git, publish, release, deploy, or touch production. Audit attempts require the
same baseline and candidate and may propose remediation only. Implementation
attempts can verify only a candidate already changed and committed through a
separately authorized development workflow; they require a strict ancestor
baseline, exact Git-diff reconciliation, explicit non-breaking compatibility
evidence, and a current passing exact-candidate `jstack_qa` receipt. JStack QA
remains environment hardening, not an OS or network sandbox.

All six architecture surfaces, graph relationships, evidence references,
change-amplification counts, material non-style findings, remediations, and
compatibility assessments must be complete and internally consistent.
Unsupported coverage, unresolved gaps, stale or unused objects, speculative
high severity, breaking or unsupported compatibility, fabricated QA, and
non-training changes fail closed. Evaluation returns only metadata, counts,
failure codes, and a digest. Passing Stage 4 does not prove semantic
correctness, behavior preservation, maintainability, compatibility,
vulnerability absence, remediation safety, release readiness, or production
security.

### Audit mastery Stage 5

Audit mastery Stage 5 permits only `benchmark-plan.md`,
`baseline-results.json`, and `performance-findings.json` at their exact
`.jstack-training/` paths. The Audit evaluator is static: it reads immutable
Git blobs and verifies signed receipt metadata but never runs repository code,
optimizes a target, accesses secrets, mutates Git, publishes, releases,
deploys, or touches production.

`jstack_performance_capture` is a separate developer/QA tool, not an Audit
execution escape hatch. It accepts only a discovered command after the caller
binds explicit trust to the exact current Git revision, project fingerprint,
and policy digest. No custom signer, approval token, or terminal-paste flow is
used. Execution closes stdin, scrubs inherited variables, forwards no secrets,
uses an isolated HOME, avoids a shell, bounds time and output, writes the
protocol target outside the repository, and rejects Git-visible tracked or
non-ignored repository mutation. The
output is opened without following symlinks where supported, identity-checked,
size-bounded, parsed as duplicate-free UTF-8 JSON, and normalized to finite
non-negative samples. Command stdout and stderr are reduced to digests and are
not returned.

This runner is not an OS or network sandbox and retains the current user's
filesystem and network privileges. Use a container, VM, or hardened execution
host for untrusted code. A signed capture proves only that the same live JStack
session bound the stated Git tree, discovered command, workload, local
environment metadata, and normalized sample digest. It cannot prove that the
workload is realistic, the host was isolated or idle, a timer was accurate,
the measurements generalize, or production has sufficient capacity.

The evaluator recomputes summaries, nearest-rank percentiles, budget results,
relative improvement, and guardrail regressions. Missing or altered receipts,
historical/candidate revision mismatch, different workload/command/environment
contracts, hidden outlier removal, non-finite samples, unsupported coverage,
gaps, missing current QA, and non-training dirty paths fail closed. Passing
Stage 5 grants no optimization, Git, release, deployment, or production
authority and does not prove correctness, universal performance, capacity, or
remediation safety.

### Audit mastery Stage 6

Audit mastery Stage 6 permits only `dependency-inventory.json`,
`build-trace.md`, and `supply-chain-report.json` at their exact
`.jstack-training/` paths. The evaluator reads immutable Git objects and
signed receipts. It never executes repository code, resolves dependencies,
contacts a package registry, accesses secrets, hardens a target, mutates Git,
publishes, releases, deploys, or touches production.

Tracked dependency/build inputs are independently enumerated for both bound
revisions and every represented blob's hash and size are recomputed. GitHub
Actions references and top-level permissions are parsed from the immutable
workflow bytes. Dynamic or unparseable references fail closed. Mutable
references, implicit or unsupported permissions, unbounded writes, missing
provenance, and generated-copy drift require explicit verified findings;
omitted workflows, inputs, artifacts, or controls cannot disappear behind a
model-authored coverage claim.

Advisory evidence must come from a separately approved curated
`dependency-analysis` adapter bound to the exact audit subject. Final audit
receipts retain only the adapter identity, status, version, approval-subject
digest, evidence/output fingerprints, return code, and mutation flag—never
stdout, stderr, source previews, or secret values. Missing, failed, capped,
stale, mutated, wrong-session, or mismatched scanner evidence is a no-go.
Every discovered QA command also needs a current passing exact-candidate
receipt.

The optional `osv-scanner-offline` adapter requires a pre-populated external
database path supplied through `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. JStack
rejects missing, unreadable, non-directory, or repository-contained paths and
binds the resolved path and scanner executable identity to the exact subject.
It never requests a database download. Offline mode is still process
configuration, not a host firewall.

Curated local adapter execution is not an OS or network sandbox; offline flags
do not create a host firewall. Use a container, VM, or hardened execution host
for untrusted repositories. A Stage 6 pass proves bounded inventory, workflow,
graph, provenance, generated-copy, receipt, QA, and diff-contract integrity.
It does not prove complete transitive dependency semantics, current or complete
advisory data, reproducible builds, artifact authenticity, vulnerability
absence, hardening safety, release readiness, or production authority.

### Audit mastery Stage 7

Audit mastery Stage 7 permits only `adversarial-plan.md`,
`verification-results.json`, and `false-positive-analysis.md` at their exact
`.jstack-training/` paths. Audit and its deterministic evaluator do not execute
the repository, implement a harness, develop or retain an exploit, create a
candidate, access secrets, mutate Git, publish, release, deploy, or touch
production.

Dynamic evidence must come from current-session `jstack_adversarial_capture`
receipts produced within a separately authorized trusted development or QA
workflow. The tool accepts only a discovered command at an exact reviewed Git
state and emits a closed capture containing bounded identifiers,
classifications, and SHA-256 digests. Raw inputs, payloads, source, stdout,
stderr, and secrets are forbidden. Receipts bind the exact Git commit/tree,
policy, command/fingerprint, campaign, deterministic corpus and seed, target
scope, local environment, case-set digest, and outcome-set digest.

Every case has exactly two identical classified outcomes, and the campaign
requires at least four cases across at least three categories. The evaluator
also requires complete eight-category classification, reciprocal static and
dynamic hypotheses, both confirmed and refuted dispositions, a confirmed
dynamic observation, reciprocal false-positive analysis, current passing QA
for every discovered command, and a complete passing security receipt. The
implementation drill additionally requires a strict ancestor-to-current
committed diff, exact paths, at least one added case, no removals, and stable
shared contracts and outcomes.

The local runner scrubs its environment, isolates HOME, closes stdin, and caps
time and output, but it is not an OS or network sandbox and retains the current
user's filesystem and network privileges. `none-observed` does not prove that
external effects were prevented. Use an externally enforced container or VM
for untrusted or active security testing and obtain explicit authorization for
the target. A Stage 7 pass proves bounded receipt and evidence-contract
integrity only; it does not prove vulnerability absence, exploitability,
zero-day detection, universal behavior, remediation safety, release readiness,
production safety, or production authority.

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
