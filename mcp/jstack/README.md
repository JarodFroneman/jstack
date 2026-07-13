# JStack MCP

Local JSONL stdio MCP server for JStack workflow planning, governance,
evidence, release readiness, and mastery progression.

## Boundaries

- The MCP plans and validates teams; platform tools spawn real subagents.
- It does not deploy, merge, push, restart production, or expose an arbitrary
  shell tool.
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
- `jstack_runtime_status`, `jstack_detect_project`, and `jstack_plan` can
  classify an existing non-Git directory as `artifact-only`. Every
  Git-bound receipt, policy, and release tool still requires a valid Git
  repository; audit finalization is the advisory exception and issues no
  receipt in that mode.
- Artifact-only audit planning is advisory and cannot issue a Git-bound audit
  receipt or formal release-ready result.

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

Release readiness requires an explicit base, clean commit, current passing
receipt for every discovered command, complete current and release-history
secret scan, environment-specific approval reference, rollback, and monitoring.

## Tools

The server exposes `jstack_*` tools for runtime status, project detection,
planning, team validation, policy/preflight, health/review, QA, security,
audit, context, release, quant review, and mastery. Legacy `gstack_*` aliases remain
for compatibility; upstream gstack itself is optional.

Use `tools/list` after MCP initialization for the authoritative schemas.

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

## Verify

~~~text
python smoke_test.py
~~~

The smoke test is an independent newline-delimited JSON-RPC client; it does not
reuse the server's framing implementation.
