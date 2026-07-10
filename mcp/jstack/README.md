# JStack MCP

Local JSONL stdio MCP server for JStack workflow planning, governance,
evidence, release readiness, and mastery progression.

## Boundaries

- The MCP plans and validates teams; platform tools spawn real subagents.
- It does not deploy, merge, push, restart production, or expose an arbitrary
  shell tool.
- `jstack_qa` can execute only discovered project commands after exact
  revision, fingerprint, policy, and explicit-trust checks.
- Project commands remain repository-controlled code with the current user's
  filesystem and network privileges. The scrubbed environment and isolated
  HOME are hardening, not an OS sandbox.
- Context and mastery records are atomically written under `~/.jstack` with
  private file permissions.
- `jstack_runtime_status`, `jstack_detect_project`, and `jstack_plan` can
  classify an existing non-Git directory as `artifact-only`. Every
  receipt/policy/release tool still requires a valid Git repository.

## Evidence

QA and security receipts are HMAC-signed for one server session and bind:

- canonical repository root
- explicit comparison base where supplied
- HEAD and workspace fingerprint
- policy digest and JStack version
- check/command identity and outcome
- issue time and server session

Release readiness requires an explicit base, clean commit, current passing
receipt for every discovered command, complete current and release-history
secret scan, environment-specific approval reference, rollback, and monitoring.

## Tools

The server exposes `jstack_*` tools for runtime status, project detection,
planning, team validation, policy/preflight, health/review, QA, security,
context, release, quant review, and mastery. Legacy `gstack_*` aliases remain
for compatibility; upstream gstack itself is optional.

Use `tools/list` after MCP initialization for the authoritative schemas.

## Install

From this directory:

~~~text
python install.py
~~~

The installer stages and atomically replaces `~/.codex/mcp/jstack`, backs up
the Codex config, and writes the `mcp_servers.jstack` entry using the current
Python interpreter.

Restart Codex or open a new task after installation.

## Verify

~~~text
python smoke_test.py
~~~

The smoke test is an independent newline-delimited JSON-RPC client; it does not
reuse the server's framing implementation.
