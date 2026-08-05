# JStack MCP

Local JSONL stdio MCP server for JStack workflow planning, governance,
evidence, launch assurance, release readiness, and mastery progression.

## Boundaries

- The MCP plans and validates teams; platform tools spawn real subagents.
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
- Project commands remain repository-controlled code with the current user's
  filesystem and network privileges. The scrubbed environment and isolated
  HOME are hardening, not an OS sandbox.
- Context and mastery records are atomically written under `~/.jstack` with
  private file permissions.
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

QA, security, audit, and launch receipts are HMAC-signed for one server session and bind:

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

The server exposes 50 canonical `jstack_*` tools for runtime status, project
detection, adaptive context readiness, planning, capability routing,
specialist result/handoff validation, team
validation, policy/preflight, health/review, QA, security, launch assurance,
audit, bounded loops, multi-phase programs, context, release, quant review, and
mastery. Legacy `gstack_*` aliases remain for compatibility; upstream gstack
itself is optional.

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

## Install

From this directory:

~~~text
python install.py
~~~

The installer stages all prompts, skills, MCP files, curricula, and config
before activation. Any late failure restores every affected target; successful
installs retain the previous Codex config backup and write the
`mcp_servers.jstack` entry using the current Python interpreter.

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
