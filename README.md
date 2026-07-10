# JStack

JStack is an independent Codex workflow, plugin, MCP control plane, and
deliberate-practice system for evidence-driven software delivery. Upstream
gstack can provide optional extra skills, but it is not required.

JStack does not turn generated code into enterprise code by declaration. It
raises the probability of professional outcomes by enforcing scope, review,
tests, security evidence, release controls, and honest residual-risk reporting.

## Commands

- `/j-stack-dev`: one Lead Engineer, no subagents.
- `/jstack-subagents`: Lead plus a right-sized team, normally two or three
  specialists.
- `/jstack-full-team`: all 11 professional roles, dispatched in controlled
  waves.

Command choice is authoritative. All three modes use the same enterprise
quality bar.

## What 0.2 Enforces

- MCP newline-delimited JSON-RPC transport tested by an independent client.
- One canonical source with deterministic plugin copies and BOM/drift checks.
- Non-overridable policy floors.
- Committed `base..HEAD`, staged, unstaged, and untracked change evidence.
- Explicit-trust QA execution bound to revision, workspace, policy, and command.
- Signed session-local QA and security receipts.
- Current-tree and release-range secret scanning that fails on incomplete
  coverage.
- Release denial without an explicit distinct pre-release base, clean commit, all current QA
  receipts, complete security evidence, external approval reference, rollback,
  and monitoring.
- Actual coordination-packet, role, permission, and write-scope validation.
- A ten-stage mastery curriculum with artifacts, assistance caps, repeated
  independent attempts, and blind capstones.

## Trust Boundary

The QA runner closes stdin, avoids a shell, scrubs inherited variables, isolates
HOME, caps output/time, and kills its process group. It is not an OS sandbox:
repository code still has the current user's filesystem and network privileges.
Run untrusted projects in a container or VM.

Receipts prevent accidental or caller-side alteration during one MCP session.
They do not protect against compromise of the same user account.

## Layout

- `mcp/jstack/jstack_mcp_server.py`: canonical MCP server.
- `prompts/`: canonical slash-command prompts.
- `skills/jstack-dev/`: canonical workflow skill and references.
- `mastery/curriculum.v1.json`: canonical training curriculum.
- `plugin/`: generated umbrella plugin with portable Node/Python launcher.
- `plugins/`: three top-level alias plugins.
- `scripts/sync_artifacts.py`: generated-artifact and version enforcement.
- `scripts/install.py`: staged legacy direct installer.
- `tests/`: unit, transport, adversarial, release, mastery, and install tests.
- `jstack.enterprise.json`: this repository's policy.

## MCP Tools

Primary tools use the `jstack_*` prefix:

- project and workflow: `detect_project`, `plan`, `policy_check`,
  `preflight`, `health`, `review`
- teams: `team_plan`, `dispatch_check`
- evidence: `qa`, `security_audit`, `ship_check`,
  `release_readiness`
- continuity: `context_save`, `context_restore`
- specialist review: `quant_backtest_review`
- learning: `mastery_start`, `mastery_status`, `mastery_record`

Legacy `gstack_*` aliases remain for compatibility.

## Validate

~~~text
python scripts/sync_artifacts.py --write
python scripts/sync_artifacts.py --check
python -m compileall -q mcp scripts tests
python -m unittest discover -s tests -v
python mcp/jstack/smoke_test.py
~~~

CI runs these checks on macOS, Linux, and Windows with Python 3.9 and 3.12.

## Install

### Codex Plugins

Register `plugin/` and each directory under `plugins/` in a personal
marketplace, then install:

~~~text
codex plugin add jstack@personal
codex plugin add j-stack-dev@personal
codex plugin add jstack-subagents@personal
codex plugin add jstack-full-team@personal
~~~

Restart Codex or open a new task after plugin/MCP changes.

### Legacy Direct Install

~~~text
python scripts/install.py
~~~

This installs prompts, the umbrella skill, MCP server, curriculum, and MCP
configuration under `~/.codex` using staged directory replacement and config
backups.

## Mastery

Start at Stage 0:

1. Call `jstack_mastery_start`.
2. Use `jstack_mastery_status` to select the next drill.
3. Complete the real task and required artifacts.
4. Gather commit-bound QA/security evidence.
5. Record independently cited assessment with `jstack_mastery_record`.

Read [the mastery system](docs/mastery-system.md) for stages, scoring,
advancement, and capstones. The profile is a local deliberate-practice record,
not an accredited credential.

## Governance

See [architecture](ARCHITECTURE.md), [security](SECURITY.md),
[contributing](CONTRIBUTING.md), and [changelog](CHANGELOG.md).
