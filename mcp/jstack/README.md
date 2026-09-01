# JStack MCP

Local JSONL stdio MCP server for JStack workflow planning, governance,
evidence, launch assurance, release readiness, and mastery progression.

## Boundaries

- The MCP plans and validates teams; platform tools spawn real subagents.
- The repository's `evals/` Proof Plane is development infrastructure and is
  not copied into this installed MCP. It adds no tool, model/scanner client,
  network importer, execution authority, or real-project quality claim.
- Capability packs attach task-specific methods and evidence to existing roles;
  they never grant tools, write access, path scope, or release authority.
- It does not create repositories, change remotes, commit, push, create pull
  requests, merge, tag, release, deploy, restart production, mutate external
  systems, or expose an arbitrary shell tool.
- Those actions remain separate from readiness evidence and may be performed
  only within explicit user scope plus ordinary host/provider permissions.
  JStack issues no custom challenge, token, signer command, or execution permit.
- Static audit collection and finalization are read-only and perform no network
  work. They expose curated adapter discovery and exact-subject approved fixed
  execution, never caller-defined commands. Approved adapters are trusted-code
  execution with host privileges; offline flags are not a firewall.
- `jstack_qa` can execute only discovered project commands after exact
  revision, fingerprint, policy, and explicit-trust checks.
- `jstack_performance_capture` uses the same trust boundary, accepts only a
  discovered command and closed sample protocol, writes its fixed output
  outside the repository, rejects Git-visible tracked or non-ignored mutation,
  and signs exact Git, workload,
  command, local-environment, and capture digests. It is a developer/QA tool;
  Audit never invokes it as execution authority.
- Project commands remain repository-controlled code with the current user's
  filesystem and network privileges. The scrubbed environment and isolated
  HOME are hardening, not an OS sandbox.
- Context and mastery records are atomically written under `~/.jstack` with
  private file permissions.
- Project Intelligence state is atomically written under
  `~/.jstack/project-intelligence` with private file permissions. Its managed
  Graphify provider uses only pinned local AST extraction and static HTML
  export, receives no host API or proxy credentials, and installs no project
  hooks, instructions, listeners, skills, or hosted-service integration.
- Audit mastery Stage 0 uses only two synthetic inert scenarios. It executes no
  repository code, accesses no network or secrets, permits only declared
  `.jstack-training/` artifacts, and grants no remediation or production
  authority.
- Audit mastery Stage 1 statically validates an exact-Git-bound repository map,
  source-line citation hashes, complete surface coverage, graph/trust-boundary
  integrity, and generated-artifact provenance. It performs no scan or
  execution, returns no raw source content, permits only three declared
  `.jstack-training/` artifacts, and grants no remediation or production
  authority.
- Audit mastery Stage 2 validates exact-Git-bound correctness reports across
  logic, state transitions, error handling, and reliability. Strong claims need
  hash-verified source citations, violated invariants, reciprocal static or
  exact-QA reproductions, and complete regression plans. It returns metadata,
  not raw source or reproduction output; allows only three declared training
  artifacts; and grants no remediation or production authority.
- Audit mastery Stage 3 validates a static exact-Git-bound threat model with
  complete STRIDE classification, assets, adversaries, trust boundaries,
  controls, reciprocal abuse cases and verified reachable paths, critical
  blockers, pinned versioned standards mappings, and secret-safe narratives.
  It executes and exploits nothing, returns only metadata, allows only three
  declared training artifacts, and grants no remediation or production
  authority.
- Audit mastery Stage 4 validates exact baseline/candidate Git architecture
  evidence across six surfaces, graph relationships, material non-style
  findings, change-amplification counts, compatibility assessments, exact
  candidate diffs, and current QA receipts. Static audits propose only;
  implementation attempts verify a candidate committed by a separately
  authorized development workflow. The evaluator executes no repository code,
  returns only metadata, allows only three declared training artifacts, and
  grants no remediation or production authority.
- Audit mastery Stage 5 validates signed, retained performance samples against
  a closed workload and exact Git revisions. It recomputes summaries, budgets,
  relative improvement, and guardrail regressions, requires current QA, returns
  only evaluation metadata, permits only three declared training artifacts,
  and grants no benchmark-execution, optimization, or production authority.
- Audit mastery Stage 6 validates an exact tracked dependency/build inventory,
  GitHub Actions pins and permissions, source-to-artifact graphs, provenance,
  generated-copy drift, current sanitized dependency-analysis receipt
  evidence, every discovered QA command, and one separately committed
  hardening diff. The evaluator runs no repository code or registry request,
  returns only metadata, permits only three declared training artifacts, and
  grants no dependency-update, Git, release, deployment, or production
  authority.
- Audit mastery Stage 7 validates exact-revision, signed deterministic
  adversarial captures, eight-category coverage, reciprocal hypotheses and
  false-positive assessments, every discovered QA command, a current passing
  security receipt, and strict baseline/candidate harness comparison. Audit
  performs no target execution or harness implementation; local capture is not
  an OS or network sandbox, and a pass grants no vulnerability-absence,
  exploit, remediation, release, deployment, or production claim.
- Audit mastery Stage 8 reconciles a fresh exact-HEAD release-audit receipt
  with the finalized result, deterministic SARIF, canonical engineering and
  executive Markdown, and a priority-first risk register with explicit open
  and accepted-risk governance. The controls drill compares the candidate
  against a prior passed Git-immutable Stage 8 result and rejects blocker,
  severity, or priority regressions. Audit remains read-only and grants no
  remediation, risk-acceptance, Git, publication, release, deployment, or
  production authority.
- The optional `osv-scanner-offline` curated adapter provides cross-ecosystem
  advisory evidence from a pre-provisioned external local database. It
  requires `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`, enforces OSV offline mode,
  binds the database path and executable identity, and performs no database
  download.
- `jstack_context_readiness` is read-only. It inspects a structured brief,
  returns at most three material questions with recommended defaults, and
  stores no raw conversation or source content in its session receipt. The
  returned normalized brief is separately digest-verified by planning so facts,
  assumptions, and audit selectors stay visible and cannot be changed silently.
- Program state is stored privately under `~/.jstack/programs`; the live
  manifest never mounts into the project repository.
- `jstack_runtime_status`, `jstack_detect_project`, and `jstack_plan` can
  classify an existing non-Git directory as `artifact-only`. Every
  Git-bound receipt, policy, and release tool still requires a valid Git
  repository; audit finalization is the advisory exception and issues no
  receipt in that mode.
- Artifact-only audit planning is advisory and cannot issue a Git-bound audit
  receipt or formal release-ready result.
- Specialist telemetry stores bounded metadata and server-derived digests. Its
  schema has no raw prompt, message, tool-argument, model-output, or arbitrary
  log fields, and rejects recognized raw-content keys and secret-like values.

## Evidence

QA, performance, security, audit, and launch receipts are HMAC-signed for one server session and bind:

- canonical repository root
- explicit comparison base where supplied
- HEAD and workspace fingerprint
- policy digest and JStack version
- check/command identity and outcome
- issue time and server session

Context-readiness receipts additionally bind the normalized goal and brief
digests, workflow, risk tier, project mode, tool version, and current Git state
when available. They are planning evidence only and never authorize actions.

Audit receipts additionally bind controls, profile, scope, required domains,
adapter inventory, inspected-input manifest, coverage, findings, server
evaluation time, active suppression expiries, result status, and completeness.
Release-profile receipts also bind complete repository scope and the release
range digest. They attest these deterministic facts, not semantic truth.

Specialist result receipts bind exact role/capability routing, permissions,
required evidence, minimized telemetry, catalog/selection digests, and current
Git state. A specialist handoff receipt requires complete current role coverage
and resolved contradictions. These receipts attest validation and binding, not
semantic truth or release permission.

Launch v2 sessions bind the accountable surface/risk declaration, static hint
and reconciliation digests, catalog and selection, target environment, bounded
URL, and immutable deployment fingerprint. Per-requirement evidence receipts
bind structured assertions, producer identity/independence, completeness,
truncation, semantic digest, artifact hash, and JStack-derived outcome without
returning content. Final receipts require every blocker/required composite
requirement. High risk requires an independent scanner; critical risk also
requires independent human security review and permits no waiver.

Release readiness requires an explicit base, clean commit, current passing
receipt for every discovered command, complete current and release-history
secret scan, a current production launch receipt, environment-specific approval
reference, rollback, and monitoring. Policy-triggering launch surfaces also
require a release-profile audit.
Even a ready result reports `executionAuthorized=false`; evidence is not
execution.

## Tools

The server exposes 65 canonical `jstack_*` tools for runtime status, project
detection, two-stage Prompt Compilation, adaptive context readiness, planning, capability routing,
specialist result/handoff validation, team
validation, policy/preflight, health/review, QA, performance and adversarial capture, security, launch assurance,
audit, bounded loops, multi-phase programs, context, release, quant review, and
mastery, and Product Interface reference, candidate contracting/finalization,
and Product Interface reference, candidate, and motion specification/finalization lifecycles. The frozen 52 legacy `gstack_*`
aliases remain for compatibility; `jstack_prompt_compile` and the six UI tools are canonical-only
and upstream gstack itself is optional.

The five Project Intelligence tools are `jstack_graph_index`,
`jstack_graph_query`, `jstack_graph_impact`, `jstack_graph_refresh`, and
`jstack_graph_finalize`. They bind a pinned private Graphify AST graph to the
exact Git tree, dirty fingerprint, policy, provider catalog, and original
change base. Only source-anchored `EXTRACTED` edges are strong evidence;
inferred, ambiguous, and unanchored edges remain advisory. These tools select
context and validate evidence only. They do not replace source reads, tests,
scanners, audit, review, or human judgment and authorize no action.

Prompt Compiler `1.1.0` / execution template v2 renders the same professional
prompt-engineering standard for all seven workflows and adds a policy-traced
secure-development baseline only to authorized implementation/fix work or
explicit plan-only creation of new software or a development workspace. The
baseline uses existing JStack security capabilities proportionately, cannot
expand authority, and does not turn a bypass into evidence or claim attack
immunity.

Current JStack releases have no custom action-approval tools. JStack never asks for an approval
token, signing key, challenge file, mailbox response, or terminal command.
External operations use explicit user scope and normal host/provider
permissions.

The launch tools are `jstack_launch_assess`,
`jstack_launch_evidence_register`, and `jstack_launch_finalize`. They select
and validate evidence only; they perform no network, provider, payment,
deployment, or production action.

Program tools add project-derived phase DAGs, exact child-loop proofs,
conversational human-gate records, external artifact evidence, pause-aware
active-time budgets, revisions, idempotent mutations, and final integrated
acceptance. They do not hardcode a phase count or domain roadmap.

Use `tools/list` after MCP initialization for the authoritative schemas.
The capability-specific entry points are `jstack_capability_catalog`,
`jstack_specialist_result`, and `jstack_specialist_handoff_check`; planning,
audit, and loop tools also expose capability fields.

`jstack_capability_catalog` also returns the separate
`jstack.methodology-capability.catalog.v1`. Existing `jstack_plan` and
`jstack_team_plan` deterministically select its seven Stage 8 methods, route
required specialists and evidence through Team Composer, and return a
`jstack.methodology-plan.v1`. The signed Team Plan receipt binds the catalog
and selection digests. Methods contain no upstream executable prompt, provider
invocation, persistence, or action authority.

Stage 9 uses the existing dispatch and specialist-result tools to enforce
Root-Cause Investigation. When a mutating Team Plan selects that method,
`jstack_dispatch_check` requires `dispatch_phase="investigation"` before any
writer can run. The exact read-only investigator submits
`jstack.investigation.v1` through `jstack_specialist_result`; only a passing,
unchanged-candidate, digest-only certification can be supplied as
`investigation_receipt` for `dispatch_phase="remediation"`. Three consecutive
falsified or inconclusive attempts require a revised trace and explicit
`hypothesis-limit` stop; a fourth attempt is invalid. Diagnosis-only and
unresolved results remain non-mutating. See
`docs/integration/gstack/ROOT_CAUSE_INVESTIGATION.md`.

Stage 10 uses the existing `jstack_ui_contract` entry point for bounded
Product/Design intelligence. Its optional `design_decision` input records one
directed selection or two/three source-traceable alternatives with an explicit
human-selected direction. The normalized decision retains only digest-bound
sources and approval, rejects unapproved established-system replacement and
reference-selection drift, and carries no implementation, provider,
candidate-mutation, production, Git, release, deployment, or external-action
authority. Ordinary and reference-only callers remain on closed UI-contract
v1/v2; design-bound callers use additive v3/v4. See
`docs/integration/gstack/PRODUCT_DESIGN_DEPARTMENT.md`.

The full staged integration and release-readiness documentation is indexed at
`docs/integration/gstack/README.md`. It distinguishes operating mode, profile,
scope, risk, specialist, canonical role, capability, provider, evidence, and
physical-agent concerns while retaining one JStack authority kernel. The
empirical protocol is present but remains `NOT_MEASURED`; MCP availability or
a passing receipt does not establish a comparative claim or authorize release.

Product Interface evidence producers use the packaged
`ui-evidence.v1.schema.json`, `ui-objective-result.v1.schema.json`, and
`ui-product-observation.v1.schema.json` contracts. Objective results bind the
exact build, runtime, producer, surface/platform, contracted matrix cells, and
digest-bound structured assertion measurements. Product observations carry
the same candidate and producer binding. All referenced bytes remain beneath
the server-selected private evidence root; receipts return normalized digests
and counts, never raw artifact content.

Motion evidence producers use `ui-motion-result.v1.schema.json` and
`ui-motion-evidence.v1.schema.json`. The host browser or native harness writes
ordinary and reduced-mode measurements for every specified interaction and
platform; `jstack_ui_motion_finalize` validates those private canonical bytes
against the clean candidate and `jstack.ui.motion-spec.v1`, derives the closed
`jstack.ui.motion-audit.v1` object, writes a deterministic script-free private
HTML report, and returns `jstack.ui.motion-finalization.v1`. JStack does not
operate the capture harness or certify producer honesty or aesthetic quality.

Evidence Builder producers use the packaged
`ui-reference-contract.v1.schema.json`,
`ui-reference-bundle.v1.schema.json`, and
`ui-reference-analysis.v1.schema.json` contracts. Their private source bundles
can contribute only a digest-bound reference to a later UI contract; they never
satisfy candidate screenshots, objective checks, security evidence, or release
approval. Reference-free UI contracts retain the v1 shape; reference-bound
contracts use the packaged additive `ui-contract.v2.schema.json` successor.
Optional human-selected Product/Design decisions use the closed
`ui-design-decision.v1.schema.json` contract and additive UI-contract v3, or v4
when a reference is also bound. None of these receipts authorizes
implementation or production mutation.

## Install

From a complete release checkout, use the top-level installer:

~~~text
python scripts/install.py
~~~

Provision the optional pinned local Graphify provider with Python 3.10 or
newer only when Project Intelligence is required:

~~~text
python scripts/install.py --with-project-intelligence
~~~

The runtime is isolated under `~/.jstack/tools/graphify`; it is not a Codex
skill and does not add a command. The ordinary installer remains offline with
respect to Graphify.

The transactional installer stages all prompts, skills, MCP files, curricula,
and config before activation. Any late failure restores every affected target;
successful installs retain the previous Codex config backup and write the
`mcp_servers.jstack` entry using the current Python interpreter. The local
`mcp/jstack/install.py` file is only a compatibility router to that top-level
installer when it is run from a complete checkout. An already-installed MCP
copy deliberately refuses to update itself.

Restart Codex or open a new task after installation.

Human program gates are resolved directly after an explicit decision in the
active conversation. The caller supplies the named approver, required role,
decision, and bounded reference; JStack binds and timestamps the record. No
identity configuration, shared key, signer, token, or terminal step exists.

## Verify

~~~text
python smoke_test.py
~~~

The smoke test is an independent newline-delimited JSON-RPC client; it does not
reuse the server's framing implementation.
