# JStack MCP

Local JSONL stdio MCP server for JStack workflow planning, governance,
evidence, release readiness, and mastery progression.

## Boundaries

- The MCP plans and validates teams; platform tools spawn real subagents.
- Capability packs attach task-specific methods and evidence to existing roles;
  they never grant tools, write access, path scope, or release authority.
- It does not create repositories, change remotes, commit, push, create pull
  requests, merge, tag, release, deploy, restart production, mutate external
  systems, or expose an arbitrary shell tool.
- Every such action defaults to blocked and requires its own independently
  signed exact challenge, unchanged Git/policy/branch/remote state, fresh
  provider observation, destructive one-time consumption, and short-lived
  permit. The MCP issues the permit but never executes the action.
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

QA, security, and audit receipts are HMAC-signed for one server session and bind:

- canonical repository root
- explicit comparison base where supplied
- HEAD and workspace fingerprint
- policy digest and JStack version
- check/command identity and outcome
- issue time and server session

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

Release readiness requires an explicit base, clean commit, current passing
receipt for every discovered command, complete current and release-history
secret scan, environment-specific approval reference, rollback, and monitoring.
Even a ready result reports `executionAuthorized=false`; evidence is not action
authority.

## Tools

The server exposes `jstack_*` tools for runtime status, project detection,
planning, capability routing, specialist result/handoff validation, team
validation, policy/preflight, health/review, QA, security,
audit, bounded loops, multi-phase programs, context, release, quant review, and
mastery. Legacy `gstack_*` aliases remain for compatibility; upstream gstack
itself is optional.

The external-action tools are `jstack_external_action_challenge`,
`jstack_external_action_authorize`, and `jstack_external_action_consume`. They
bind exactly one action to provider, owner, repository, visibility, remote,
branch, tag, full commit, environment, current project state, policy, version,
and MCP session. Broad task or phase approval is never accepted.

Program tools add project-derived phase DAGs, exact child-loop proofs,
signed-local human gates, external artifact evidence, pause-aware active-time
budgets, revisions, idempotent mutations, and final integrated acceptance.
They do not hardcode a phase count or domain roadmap.

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

Human program gates additionally require a private identity configuration and
environment-held approver keys. Use the included
`templates/jstack.program-identities.json`; named operators sign exact
challenges with `sign_program_approval.py` outside Codex.

Protected external actions use a separate private identity configuration. Use
`templates/jstack.external-action-identities.json`, set
`JSTACK_EXTERNAL_ACTION_IDENTITY_CONFIG`, and have the named operator run
`sign_external_action_authorization.py` outside Codex with the full returned
challenge digest. Never expose its key to Codex.

## Verify

~~~text
python smoke_test.py
~~~

The smoke test is an independent newline-delimited JSON-RPC client; it does not
reuse the server's framing implementation.
