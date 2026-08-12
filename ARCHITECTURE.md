# JStack Architecture

## Authority

Canonical sources live in:

- `mcp/jstack/jstack_mcp_server.py`
- `mcp/jstack/capabilities/`
- `mcp/jstack/context_readiness/`
- `mcp/jstack/audit/`
- `mcp/jstack/launch/`
- `mcp/jstack/loop/`
- `mcp/jstack/program/`
- `mcp/jstack/schemas/`
- `prompts/`
- `skills/jstack-dev/`, `skills/jstack-audit/`, and `skills/jstack-loop/`
- the engineering, audit, and loop curricula under `mastery/`
- `mcp/jstack/templates/`

Development-only evaluation infrastructure lives under `evals/`. It is an
authoritative source for Proof Plane contracts and tests, but it is not part of
the installed MCP or command-plugin runtime.

`scripts/sync_artifacts.py` generates and verifies plugin copies. It operates
only on Git-tracked and explicitly declared files, compares exact generated
tree inventories, and rejects drift, stale generated files, BOMs, malformed
JSON, and version mismatch.

## Control Plane

The MCP server uses newline-delimited JSON-RPC over stdio. It contains:

- command/risk routing and enterprise gates
- inspect-first adaptive context readiness with source attribution,
  assumption disclosure, bounded questions, and stale-state planning receipts
- project and policy inspection
- team planning and coordination validation
- deterministic role-bound capability routing and specialist handoff validation
- QA command discovery and explicitly approved execution
- current-tree and release-range secret scanning
- risk-tiered launch profiles, bounded surface-hint reconciliation, structured
  assertion evidence, audit-owned scanner normalization, and release-consumable
  launch finalization
- deterministic audit collection and evidence-bound finalization
- deterministic audit-mastery Stage 0 classification for CIA, authorization,
  hostile-repository, execution, disclosure, and non-authority boundaries
- deterministic audit-mastery Stage 1 validation for exact Git source binding,
  eight-surface coverage, hash-verified source-line citations, graph and trust-
  boundary integrity, generated-artifact provenance, explicit gaps, and
  non-authority limitations
- deterministic audit-mastery Stage 2 validation for exact Git source binding,
  four correctness surfaces, hash-verified citations, invariant and
  reproduction reciprocity, exact-QA receipt matching, regression completeness,
  and non-authority limitations
- deterministic audit-mastery Stage 3 validation for exact Git source binding,
  complete STRIDE classification, asset/adversary/trust/control modeling,
  reciprocal abuse cases and verified reachable attack paths, critical-blocker
  enforcement, pinned standards mappings, secret-safe narratives, and static
  non-authority limitations
- deterministic audit-mastery Stage 4 validation for baseline/candidate Git
  binding, six architecture surfaces, revision-bound citations, architecture
  graph integrity, material non-style findings, change-amplification counts,
  exact candidate diffs, compatibility evidence, current QA bindings, and
  separate Audit/remediation authority
- deterministic audit-mastery Stage 5 validation for signed exact-Git,
  workload, discovered-command, local-environment, and sample binding;
  recomputed statistics and budgets; complete performance-surface coverage;
  exact candidate diffs; current QA; guardrail regressions; and separate
  Audit/capture/optimization authority
- deterministic audit-mastery Stage 6 validation for exact tracked dependency
  and build-input enumeration, immutable GitHub Actions references, explicit CI
  permissions, source-to-artifact graphs, provenance, generated-copy drift,
  signed no-mutation dependency-analysis evidence, complete QA, exact candidate
  diffs, and separate Audit/hardening/release authority
- deterministic audit-mastery Stage 7 validation for exact-revision signed
  adversarial campaigns, two-run case determinism, eight-category coverage,
  reciprocal hypothesis/false-positive analysis, complete QA and security
  receipts, baseline/candidate harness comparison, and separate
  Audit/capture/harness/production authority
- deterministic audit-mastery Stage 8 validation for exact current release-
  audit receipt/result reconciliation, stable finding fingerprints,
  deterministic SARIF and Markdown projections, priority-first risk ownership,
  explicit accepted-risk governance, derived go/no-go decisions, prior-
  validated baseline/candidate remediation comparison, complete QA/security,
  and separate Audit/remediation/risk/release/production authority
- semantic goal-readiness assessment and Git-bound start/revision receipts
- durable bounded loop contracts, checkpoints, convergence breakers, and
  evidence-bound finalization
- durable Program -> Phase DAGs, intervention gates, child proofs, and final
  integration acceptance
- host-native action safety with no JStack approval token or terminal ceremony
- commit-bound HMAC evidence receipts
- release readiness evaluation
- local context and mastery records

The MCP never spawns platform subagents and never performs repository, Git,
provider, deployment, or production actions. Codex's platform tools perform
real dispatch and action execution only after the applicable JStack boundary.

## Proof Plane Development Boundary

The Proof Plane measures JStack from outside the installed product. Its
alpha.10 foundation consists of five closed v1 contracts, a six-family public
development manifest, a raw-byte content lock, and an inert deterministic mock
runner/scorer. The existing 12-fixture synthetic audit corpus remains Tier 0;
it validates scoring protocol behavior and is not represented as a
repository-level host benchmark.

`scripts/check_product_boundaries.py` proves that the product still has the
five named commands, 52 canonical MCP tools, 52 compatibility aliases, 11
roles, 18 capability packs, 47 launch controls, 22 launch surfaces, and a
standard-library core. It also rejects vendor SDKs, network-capable core
imports, packaged `evals/` content, model or scanner execution in the Proof
Plane, and Proof Plane filesystem mutation.

`scripts/check_contract_compatibility.py` compares the current server with the
alpha.9 snapshot: command and plugin layouts, every canonical request-schema
digest, legacy aliases, published core-schema bytes, protocol versions, and
persisted-state markers. Alpha.10 therefore changes the reported release
version without changing a prior public request contract in place.

The scorer consumes already-produced run and blinded-review envelopes. It
retains failed, blocked, and timed-out runs, requires equal limits for
controlled pairs, and reports raw counts plus intervals rather than a single
marketing score. Envelopes contain no source, prompts, model output, command
output, or human identity. Real repository execution, source fetching, model
clients, external scanners, host comparisons, pilots, holdout governance, and
evidence bridges remain outside the alpha.10 scope and cannot inherit JStack
authority merely by integrating later.

## Adaptive Context Protocol

`jstack_context_readiness` is a shared read-only intake contract for Dev,
Subagents, Full Team, and Audit. It accepts structured facts tagged as user,
repository, policy, external evidence, or inference; assumptions remain a
separate list. The tool returns `ready`, `proceed_with_assumptions`,
`needs_context`, or `needs_confirmation`, with no more than three material
questions per round and a reason plus recommended default for each.

Ready receipts contain only digests and binding metadata. Callers pass the
separate bounded `normalizedBrief` into planning, where its digest, goal,
workflow, and risk are verified so facts and assumptions stay visible without
being embedded in the receipt. Audit briefs additionally bind every explicitly
supplied profile, scope, focus, and base selector. Git-backed receipts
bind HEAD and the complete project fingerprint; artifact-only receipts bind the
resolved project path and explicit evidence limitation. Any material goal,
workflow, tool-version, project, or Git-state change invalidates the receipt.
High-risk defaults fail closed without explicit conversational confirmation.

Loop and Program retain their stronger semantic contracts as the orchestration
variant of the same gate. They reuse source-attributed context and bounded
questions rather than creating a second user-visible intake round. The protocol
adds no command, role, write permission, raw conversation storage, approval
token, or terminal ceremony.

## Specialist Capability Protocol

The capability registry upgrades the five existing workflows without creating
another command or another source of permissions. A core role remains the unit
of accountability and authority. The registry deterministically attaches at
most four applicable capability packs to each selected role from the goal,
risk classification, catalog priorities, default-role rules, and any permitted
explicit IDs.

Each pack is data: methods, required evidence kinds, stop conditions, audit
domains, loop controls, allowed roles, and `permissionMode: inherit-role`.
Strict catalog validation rejects unknown fields, unsafe source paths, invalid
patterns, unknown roles, duplicate identifiers, and any attempt to grant
authority. Canonical catalog and selection digests make routing reproducible
and bind it into downstream receipts.

`jstack_specialist_result` validates one role's structured result and minimized
telemetry, enforces its evidence and write contract, checks a stable Git
subject, and issues a session-local receipt. The server derives telemetry input
and output digests. The telemetry schema has no raw-content fields and rejects
recognized raw-content keys and secret-like values.

`jstack_specialist_handoff_check` recomputes the expected team and capability
plan, validates complete current receipt coverage, rejects overlapping change
ownership and unresolved contradictions, and issues one team handoff receipt.
The Lead may record an evidence-referenced resolution, but cannot bypass a
missing role, invalid signature, stale project state, or failed specialist
result. These receipts attest structural validation and binding, not semantic
truth or release authority.

## Launch Assurance Protocol

The active launch registry contains exactly 47 versioned controls across
security, email, findability, speed, analytics, legal, and final-test
categories. An accountable profile declares `core`, every applicable one of 22
surfaces, and a low, medium, high, or critical risk tier. Surface and policy
floors cannot be lowered. Bounded static detection returns content-free hints;
detected omissions require accountable reconciliation.

Assessment requires a clean committed candidate, explicit base, and immutable
deployment fingerprint. Evidence registration accepts only bounded structured
v2 JSON, provider-neutral scanner JSON, or SARIF 2.1.0 inside the project or
private evidence directory. The evaluator derives outcomes from required
assertions and returns no raw artifact content. Arbitrary files, prose, and
caller-written outcomes cannot pass.

Controls can contain multiple risk-active evidence requirements. Finalization
revalidates each receipt against Git, policy, catalog, selection, risk,
deployment, surface-hint, reconciliation, environment, target, and server
session. High-risk security controls are blockers and require an independent
scanner. Critical risk additionally requires independent human security review
and permits no waiver.

Production release readiness consumes the passing launch receipt. Public-web,
commercial, payment, and regulated-data profiles elevate a repository-wide
release audit to a mandatory gate by default. Launch tools perform no network,
payment, provider, deployment, or production action and never expand the
user's explicit task scope.

## Loop Protocol

Codex Goal mode is the continuation engine. The JStack loop protocol is the
contract and convergence layer around one explicit delivery mode. It stores
private state outside the repository, binds contracts to the starting commit
and policy, derives changed paths from Git, validates current receipts, and
returns a bounded decision after each iteration.

Before state creation, the goal-readiness tool builds a source-attributed,
domain-aware context, returns at most three prioritized questions per round,
and requires exact-digest confirmation for ambiguity or elevated risk. Start
and material revision require a short-lived receipt bound to that semantic
contract and the current Git/policy subject.

Readiness also binds a deterministic `capabilityContract`: catalog and
selection digests, goal digest, execution mode, exact role assignments,
explicit IDs, audit domains, loop controls, and the no-permission-expansion
invariant. Changing capabilities is a material revision. Multi-agent
checkpoints and finalization require a current specialist handoff receipt that
matches the durable contract and Git state.

Write loops require a clean start and an exclusive repository lease. L3 also
requires a linked worktree, low risk, bounded paths, and QA, security, audit,
and review criteria. Contract revisions reset completion evidence. Completion
never implies release authorization.

The lease is per resolved Git checkout, so explicitly isolated linked
worktrees can operate independently. The original commit remains the exact
merge-base boundary. Contract history, the current snapshot, and every event
head are mutually digest-bound; a pending transaction journal replays an
interrupted multi-file commit.

Approval-paused loops release their write lease and suspend active elapsed
time. An approved resume revision must reacquire the lease before mutation.

## Program Protocol

The program protocol composes bounded loops into a project-derived dependency
graph. It accepts no fixed roadmap: phase count, dependencies, staffing, gates,
and outputs are exact confirmed contract data subject to enterprise ceilings.

Each phase binds one active child loop with an exact matching goal, execution
mode, autonomy, risk, path scope, and acceptance contract. Completion requires
both a current session receipt and validated durable child-loop attestation.
Declared outputs are hashed at phase completion and revalidated before program
completion.

Human decisions are recorded from the active conversation with named roles,
quorum, contract binding, references, and freshness. External gates use
bounded hashed artifacts and provenance.
Waiting states pause active program time. Revisions invalidate changed phases
and all transitive dependants while preserving unaffected current proof.

State-changing program calls use transaction-bound idempotency keys. Program
contracts, snapshots, events, operation records, and pending transactions live
under `~/.jstack/programs` and fail closed on integrity drift. The live program
manifest never mounts into the Git repository.

## Host-Native Action Safety

JStack does not maintain a parallel approval system. There are no JStack
challenge, authorize, consume, signer, mailbox, token, or terminal-approval
components. Repository, Git, provider, deployment, and production operations
are performed by the host only when they fit the user's explicit request and
the host/provider's normal permissions.

The MCP reports evidence and readiness separately from execution. A passing
audit, launch receipt, release-readiness result, human gate, specialist
handoff, loop receipt, or program receipt never invokes an external operation.
The accountable Lead resolves exact targets and rechecks state before
irreversible work. Provider branch protection, protected environments,
least-privilege credentials, and host isolation remain the enforcement layer
for production-grade controls.

## Audit Protocol

`jstack_audit` creates a state-bound coverage contract and signed audit session.
Its bounded focus and optional explicit capability IDs route only through the
read-only Reviewer, QA, and Security roles. Capability domains may strengthen
required coverage but cannot remove profile, control-catalog, or policy
requirements.
`jstack_audit_finalize` validates repository-relative evidence, coverage,
findings, suppressions, and current state before deriving a result and, for Git
projects, issuing an audit receipt. The deterministic MCP validates evidence; it
does not claim to perform semantic model reasoning.

The audit command uses a two-pass agent boundary: candidate generation followed
by challenge and verification. Artifact-only audits are advisory and cannot
issue a Git-bound receipt or a formal release-ready result.

Audit mastery Stage 0 is separate from an audit session. It accepts one hashed
closed-schema `security-orientation.json` from `.jstack-training/`, validates
it against an exact built-in scenario contract, and records only failure codes
plus an evaluation digest. Its two inert scenarios perform no repository
execution or network operation and grant no remediation or production
authority. Advancement requires both distinct scenario IDs as the latest two
eligible independent attempts.

Audit mastery Stage 1 is also separate from an audit session. The operator
produces `system-map.md`, `trust-boundaries.md`, and a closed-schema
`coverage-matrix.json` under `.jstack-training/` without executing repository
code, using the network, accessing secrets, or changing the mapped source.
The machine-readable map binds to the current Git HEAD and tree; enumerates
architecture, entry points, data flows, trust boundaries, tests, dependencies,
build/release paths, and generated artifacts; and cites current tracked regular
files by line range and SHA-256. The evaluator validates unique identifiers,
node/flow/boundary references, generated source provenance and drift risk,
complete coverage, empty gaps, and exact limitations. It returns only counts,
failure codes, immutable subject metadata, and an evaluation digest. Two
consecutive independent passing attempts are required for advancement.

The Stage 1 Git tree is the immutable source subject. The full project
fingerprint is recorded separately with each attempt; it intentionally includes
the training artifacts and therefore is not embedded self-referentially inside
`coverage-matrix.json`. Any change outside `.jstack-training/` hard-blocks the
attempt.

Audit mastery Stage 2 is a separate correctness-evidence assessment. The
operator produces closed-schema `correctness-report.json` and
`reproductions/manifest.json` plus `invariants.md` under `.jstack-training/`.
Both JSON documents bind to the current Git HEAD/tree, and the report binds the
manifest digest. The evaluator verifies four required surfaces, tracked-source
line hashes, finding/invariant/case reciprocity, strong-claim reachability and
confidence, and complete regression plans. Static counterexamples require no
execution; executed cases must match a passing current `jstack_qa` receipt by
receipt, command key, fingerprint, profile, and return code. Raw reproduction
output and extra files are rejected.

The immutable Git tree is the Stage 2 source subject while the full project
fingerprint is retained separately. Only the three exact Stage 2 artifacts may
be dirty when an attempt is recorded. The evaluator returns counts, failure
codes, subject metadata, and a digest without returning source or artifact
content. Its pass proves evidence-contract compliance, not that the diagnosis
is semantically complete or that remediation is safe.

Audit mastery Stage 3 is a separate static threat-model assessment. The
operator produces `threat-model.md`, closed-schema `security-findings.json`,
and `abuse-cases.md` at their exact `.jstack-training/` paths. The JSON binds
the current Git HEAD/tree and both narrative hashes. The evaluator requires
the OWASP Four Question method, every STRIDE category, assets and CIA
objectives, bounded adversaries, trust boundaries and flows, observed controls,
reciprocal abuse cases and attack paths, findings, and applicable pinned
standards mappings. All material objects cite current tracked source lines and
SHA-256 hashes.

Every blocker must be a verified high-confidence high/critical finding with at
least one verified reachable path containing source, sink, preconditions,
impact, boundaries, and mitigating-control review. The seeded drill requires a
critical blocker. Unsupported coverage, gaps, stale or unused evidence,
dangling or unused objects, non-reciprocal relationships, speculative high
severity, and secret-like JSON or narrative values fail closed.

The immutable Git tree remains the Stage 3 source subject while the full
project fingerprint separately captures the dirty training artifacts. Only
the three exact Stage 3 artifact paths may be dirty. The evaluator returns
counts, failure codes, subject metadata, and a digest without source or
security content. It performs no repository execution, live exploitation,
network or secret access, payload retention, remediation, publication,
release, deployment, or production action. A pass is not proof of
vulnerability absence, exploitability, zero-day detection, standards
compliance, or production security.

Audit mastery Stage 4 is a separate architecture-evidence assessment. The
operator produces `architecture-map.md`, closed-schema
`maintainability-report.json`, and `migration-outline.md` at their exact
`.jstack-training/` paths. The report binds exact baseline and candidate Git
commits and trees plus both narrative hashes. It covers module boundaries,
dependency direction, contracts and compatibility, change amplification,
testability, and migration risk. Components, dependencies, contracts, change
scenarios, material findings, remediations, and compatibility assessments cite
bounded revision-tagged source evidence loaded from immutable Git objects.

The architecture drill is static: baseline equals candidate, findings remain
open, remediations remain proposed, and QA bindings are forbidden. The
remediation drill verifies evidence about a candidate already changed and
committed by a separate authorized development workflow. Its baseline must be
a strict ancestor, the reported path set must equal the exact Git diff,
exactly one finding and reciprocal remediation must be resolved and verified,
every contract must have supported baseline/candidate compatibility evidence,
and the QA binding must match a current passing exact-candidate `jstack_qa`
receipt.

The immutable Git revisions are the Stage 4 source subjects while the full
project fingerprint separately captures the dirty training artifacts. Only
the three exact Stage 4 artifact paths may be dirty. The evaluator returns
counts, failure codes, subject metadata, and a digest without source, finding,
architecture-map, or migration content. It executes no repository code and
grants no remediation, Git, release, deployment, or production authority. A
pass proves deterministic evidence-contract and receipt integrity, not
semantic correctness, behavior preservation, architecture quality,
compatibility, vulnerability absence, remediation safety, or production
security.

Audit mastery Stage 5 is a separate performance-evidence assessment. It uses
closed `performance-results`, `performance-findings`, and performance-capture
contracts plus one non-empty hash-bound benchmark plan. The immutable Git
commits and trees are the source subjects. The workload has one canonical
digest over its input identity, seed, concurrency, warmups, measured
iterations, timeout, critical path, and realism rationale.

`jstack_performance_capture` is outside the read-only Audit role. A separately
authorized trusted development or QA workflow may select one existing
discovered command after binding the exact revision, project fingerprint, and
policy digest. JStack supplies a fixed external output file and workload
variables, then accepts only bounded UTF-8 closed-protocol JSON. It normalizes
finite non-negative samples, requires exactly one primary and at least one
guardrail metric, rejects Git-visible tracked or non-ignored repository
mutation, and signs the exact Git tree,
command fingerprint, workload digest, local-environment digest, capture
digest, metric count, and sample count. The structured capture is returned
without command stdout or stderr; the receipt is passed directly through MCP
and never through a user-generated token or terminal command.

The Stage 5 evaluator never executes repository code. It verifies historical
baseline and current candidate receipts within the same live MCP session,
recomputes every sample summary with no outlier removal and nearest-rank
percentiles, proves an explicit baseline budget violation, and—only for the
implementation drill—recomputes positive improvement and every guardrail's
regression. The implementation baseline must be a strict ancestor, captures
must share workload, command, environment, and metric contracts, and reported
paths must equal the Git diff. Both drills require current passing QA evidence.
Only the three exact Stage 5 artifact paths may be dirty.

Evaluation returns counts, subject and workload digests, failure codes, and an
evaluation digest. It does not return source narratives, artifacts, command
output, or samples. A pass proves bounded protocol integrity, not workload
realism, measurement accuracy, universal performance, production capacity,
optimization safety, release readiness, or production authority.

Audit mastery Stage 6 is a static supply-chain and build-integrity assessment.
It uses closed dependency-inventory and supply-chain-report contracts plus one
non-empty hash-bound build trace. Baseline and candidate commits and trees are
immutable source subjects. JStack enumerates every tracked path in each tree,
applies a closed cross-ecosystem classifier, reloads every represented blob,
and recomputes its SHA-256 and size. Omitted or invented manifests, lockfiles,
policies, build configurations, GitHub workflows, provenance files, or
conventional generated artifacts fail closed.

The evaluator parses every closed-form GitHub Actions `uses:` reference and
top-level `permissions:` declaration from the immutable workflow blob. Dynamic
or unparseable references fail. Mutable references, implicit or unsupported
permissions, unbounded writes, missing provenance, and generated-copy drift
must be linked to verified findings. The submitted graph must trace source,
configuration, or dependency material to every candidate artifact; every
candidate artifact has an explicit provenance record, and every discovered
generated copy is represented with recomputed exact-copy, drift, or
unverifiable status.

Dependency advisory evidence remains outside the static evaluator. A separately
approved curated audit adapter executes against an exact project subject and
returns bounded digests rather than scanner output. Audit finalization retains
only its sanitized result metadata in the signed audit receipt. Stage 6
requires that current same-session receipt to be complete, include
`supply-chain` coverage, and contain every represented passed no-mutation
`dependency-analysis` result with validated subject and zero return code. It
also requires current passing receipts for
every discovered QA command.

The optional cross-ecosystem adapter uses OSV-Scanner with offline mode and a
pre-provisioned local database outside the repository. JStack requires
`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`, rejects missing or repository-contained
database paths, and binds that resolved path plus the executable identity,
fixed command, environment, and project subject into the approval digest. It
does not download or refresh advisory data.

The audit drill keeps baseline equal to candidate and permits proposals only.
The hardening drill verifies a candidate already changed and committed by a
separate authorized development workflow: the baseline is a strict ancestor,
the path set equals the Git diff, and exactly one finding/control is resolved
with matching QA. Only the three exact Stage 6 artifact paths may be dirty.
Evaluation returns metadata, counts, failure codes, and a digest without
source, finding, scanner, dependency, or build-trace content. A pass proves
bounded protocol integrity—not complete transitive dependency semantics,
current advisory coverage, reproducible builds, artifact authenticity,
vulnerability absence, release readiness, or production authority.

Audit mastery Stage 7 is a read-only evidence-reconciliation layer over a
separately authorized adversarial capture workflow. Its closed campaign binds
the plan, deterministic corpus and seed, target scope, time/case limits,
external-effect observation policy, and isolation limitation. Its closed
capture carries only bounded identifiers, categories, classifications, and
SHA-256 digests. At least four cases across three categories must have exactly
two identical classified outcomes; raw inputs, payloads, source, secrets,
stdout, and stderr are excluded.

Each `jstack_adversarial_capture` receipt is session-local and binds an exact
Git commit/tree, policy, discovered command/fingerprint, campaign, local
environment, normalized capture, case-set digest, and outcome-set digest. The
runner uses a scrubbed environment, isolated HOME, closed stdin, process-group
timeouts, and output caps, but it retains the user's filesystem and network
privileges. `none-observed` is an evidence classification, not enforced
network isolation. Untrusted or active targets require an externally enforced
container or VM and explicit authorization.

The evaluator independently checks all eight category dispositions, complete
case ownership, static and dynamic hypothesis origins, confirmed and refuted
outcomes, reciprocal supported/false-positive assessments, current QA for
every discovered command, and one complete passing security receipt. The
audit drill uses one current capture. The harness drill requires a strict
ancestor-to-current committed diff, exact changed paths, at least one added
case, no removed cases, and unchanged shared contracts and outcomes. Only the
three exact Stage 7 artifact paths may be dirty. A pass proves bounded protocol
integrity, not vulnerability absence, exploitability, zero-day detection,
universal behavior, release readiness, production safety, or production
authority.

Audit mastery Stage 8 is an enterprise evidence-reconciliation layer over the
existing read-only release audit. `audit-result.json` must be the exact
finalized `jstack.audit.result.v1` whose coverage, findings, counts,
suppressions, threshold, status, and evaluation time are signed by a fresh
current-session receipt for the exact candidate HEAD and complete repository-
scope release profile. Because the report, SARIF, and risk register are
necessarily written after audit finalization, the evaluator tolerates only
those four exact `.jstack-training/` paths as post-receipt fingerprint drift;
any other dirty path fails closed.

The risk register uses the closed
`jstack.audit.enterprise-risk-register.v1` contract. It covers every current
finding once, orders by priority then severity, derives remediate, investigate,
or accepted-risk disposition, and requires owner/reason/future-target data for
open risk. Accepted risk must exactly reproduce the finalized fingerprint,
scope, owner, reason, approval reference, future expiry, compensating control,
and residual risk. SARIF must equal JStack's deterministic 2.1.0 projection;
the Markdown report must equal the canonical executive and engineering
projection. Go is derived only from a complete passing release audit; a
complete failing audit is no-go.

The audit drill keeps baseline equal to candidate. The controls drill verifies
a candidate already implemented and committed elsewhere: its baseline is a
strict ancestor, the Git-immutable baseline result commit and canonical JSON
SHA-256 must match a prior passed Stage 8 attempt, changed paths equal the Git
diff, at least one verified baseline fingerprint is absent from the current
signed result, the
candidate release audit passes, and no introduced blocker, severity increase,
or priority escalation is detected. Current passing QA for every discovered
command and a complete passing security receipt remain mandatory. Evaluation
retains only subject metadata, counts, digests, the derived decision, failure
codes, and an evaluation digest. It grants no code edits, risk acceptance, Git,
release, deployment, production action, or claim of vulnerability absence.

## Project Binding

Runtime health is independent from project eligibility. `runtime_status`
proves the MCP transport and session are active. Detection and planning accept
any existing directory and classify it as:

- `git`: the canonical repository root is the evidence subject.
- `artifact-only`: planning can describe direct operational evidence, but all
  Git-bound policy, receipt, context, mastery, quant, and release tools remain
  unavailable. Audit start/finalization may produce an advisory incomplete
  report, but never a Git-bound receipt or release certification.

This prevents a valid MCP mount from being misreported as unavailable while
preserving the commit-bound release trust model.

## Evidence Invariants

A receipt binds repository root, an explicit distinct pre-release base where applicable, HEAD,
workspace fingerprint, policy digest, tool version, check definition, outcome,
and server session. Any mismatch denies readiness.

Audit sessions additionally bind controls, profile, scope, required domains,
adapter inventory, and a deterministic manifest of inspected inputs. Audit
receipts bind coverage and finding digests, server evaluation time, and active
suppression expiries plus the capability catalog, selection, goal, and selected
capability IDs. Receipts retain bounded sanitized adapter-result identities,
statuses, and evidence digests but no scanner output. Release-profile receipts bind complete repository scope and the
release-range digest. The audit release gate is opt-in; QA and security receipt
compatibility is unchanged.

Specialist result receipts bind the complete role roster, exact role and
capability assignment, write scope, catalog and selection digests, result and
telemetry digests, Git subject, policy, tool version, and server session. A
handoff receipt additionally binds every accepted result receipt and structured
Lead resolution. Any missing, duplicate, stale, contradictory, or
permission-inconsistent input denies the handoff.

QA discovery is not evidence. A complete clean scan is evidence only for the
heuristics it actually ran. Missing, stale, failed, timed-out, truncated, or
inconclusive evidence never becomes a pass.

Loop completion receipts additionally bind the loop ID, contract digest,
baseline commit, completion-evidence digest, event-chain head, execution mode,
capability catalog and selection digests, the applicable specialist handoff,
autonomy, and risk tier. Durable state survives MCP restarts, but signed
receipts remain intentionally session-local and must be revalidated.

Program completion receipts additionally bind the program and contract IDs,
all phase proof digests, current final evidence, project fingerprint, and
program event head. Durable child proof is revalidated against its loop event
chain and current declared output hashes.

## Security Boundary

Git inspection neutralizes common external diff, prompt, fsmonitor, and global
configuration hooks. Scanner files are opened descriptor-first without
following symlinks where the host supports `O_NOFOLLOW`.

The shared Python QA/performance runner is not an operating-system sandbox. It closes stdin,
scrubs inherited variables, isolates HOME, avoids a shell, caps output/time, and
kills its process group. Untrusted project execution still requires a
container, VM, or host sandbox.

Specialist telemetry is bounded metadata, not a raw trace store. It may contain
identifiers, timing, status, counts, tool names/statuses, evidence references,
and server-derived digests. It rejects raw content and recognized secret-like
values, but the retained metadata can still be sensitive and inherits the same
local account boundary as other session receipts.

The same boundary applies to approved audit adapters. Static audit collection
does not execute repository code or perform network work. Adapter offline flags
are advisory process configuration; they do not remove host filesystem or
network privileges. Quick therefore rejects all adapter execution, and
untrusted verification requires an externally enforced read-only sandbox.

Program human decisions are caller-supplied conversational records. They bind
the decision to the current contract, gate, named approver role, reference
digest, and freshness window, but do not authenticate identity. Organizations
needing SSO, non-repudiation, or separation of duties should enforce those
controls in their host and provider workflows.
