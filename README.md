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
- `/jstack-loop`: a bounded, durable goal loop composed with one explicitly
  selected delivery mode.
- `/jstack-audit`: a read-only, evidence-bound audit with quick, standard,
  deep, and release profiles.

Command choice is authoritative. The three delivery modes share one enterprise
quality bar. Loop mode owns one bounded convergence contract or a
project-derived Program -> Phase DAG while the selected per-phase delivery mode
owns execution. Audit mode is a separate inspection workflow and does not edit
project code.

Invoke `/jstack-loop <goal>` for the default single-lead loop or program. State
`use JStack Subagents` or `use JStack Full Team` in the same request when that
staffing is explicitly intended; commands are never silently nested or
escalated.

The umbrella or legacy install supports `$jstack-audit` and `$jstack-loop`;
dedicated plugins use `$jstack-audit:jstack-audit` and
`$jstack-loop:jstack-loop`. Legacy direct installs also expose prompt forms.
Top-level palette labels are client-dependent and should be verified after an
actual install and restart.

## What 0.5 Enforces

- MCP newline-delimited JSON-RPC transport tested by an independent client.
- Independent runtime mount diagnostics plus explicit Git-backed and
  artifact-only project bindings.
- One canonical source with deterministic plugin copies and BOM/drift checks.
- Non-overridable policy floors.
- Committed `base..HEAD`, staged, unstaged, and untracked change evidence.
- Explicit-trust QA execution bound to revision, workspace, policy, and command.
- Signed session-local QA and security receipts.
- Current-tree and release-range secret scanning that fails on incomplete
  coverage.
- Release denial without an explicit distinct pre-release base, clean commit,
  all current QA receipts, complete security evidence, external approval
  reference, rollback, and monitoring.
- Actual coordination-packet, role, permission, and write-scope validation.
- A ten-stage mastery curriculum with artifacts, assistance caps, repeated
  independent attempts, and assessor-signed blind capstones.
- Deterministic audit sessions and finalization bound to repository state,
  policy, controls, scope, coverage, and stable findings.
- A separate ten-stage audit mastery track with atomic migration of existing
  engineering profiles.
- Versioned loop contracts with explicit goals, non-goals, execution modes,
  autonomy levels, risk tiers, acceptance criteria, scopes, and limits.
- A mandatory domain-aware goal-readiness gate with source-attributed context,
  at most three targeted questions per round, exact-digest confirmation, and
  Git-bound start/revision receipts.
- Private atomic loop state, versioned contract revisions, snapshot-bound
  hash-chained events, and one active write lease per Git checkout.
- Current QA, security, audit, deterministic review, artifact, and approval
  evidence before loop completion.
- Circuit breakers for policy/scope violations, iteration and elapsed limits,
  repeated failures, stagnation, changed-file growth, and oscillation.
- Native Codex Goal composition without claiming that the MCP can prompt or
  spawn itself, plus exact complete/blocked terminal semantics.
- A phase-count-agnostic Program -> Phase DAG above bounded child loops for
  independently verified deliverables, dependencies, and long intervention
  waits.
- Exact child contract/proof binding, output hashing, transitive invalidation,
  conservative linked-worktree parallelism, and final integrated evidence.
- Signed role/quorum human gates, freshness-bound external artifact evidence,
  pause-aware active clocks, and explicit lease reacquisition after approval.
- Transactional idempotency for every program mutation and private
  snapshot-bound program state outside the repository.
- A third ten-stage loop-engineering mastery track and atomic profile v1/v2 to
  v3 migration, with independently signed blind capstones at Stage 9.

## Trust Boundary

The QA runner closes stdin, avoids a shell, scrubs inherited variables, isolates
HOME, caps output/time, and kills its process group. It is not an OS sandbox:
repository code still has the current user's filesystem and network privileges.
Run untrusted projects in a container or VM.

Receipts prevent accidental or caller-side alteration during one MCP session.
They do not protect against compromise of the same user account.

Loop state under `~/.jstack/loops/` is private local control-plane data, not a
sandbox or distributed lock. A loop completion receipt proves the current Git
state satisfied its contract in one MCP session; it never authorizes commit,
push, deployment, release, or a protected action.

Program state under `~/.jstack/programs/` has the same local-account trust
boundary. Signed-local human gates prove possession of a configured shared key,
not enterprise identity or non-repudiation. Program completion never grants
release authority.

Audit receipts attest the collected scope, validated structure, coverage, and
result calculation. They do not prove that model-authored semantic findings are
true. The existing bounded secret scanner and its security receipt retain their
original meaning.

Non-Git orchestration directories can use JStack planning in `artifact-only`
mode. Formal operator evidence still requires direct hashes, tests, backups,
immutable runtime identity, rollback, monitoring, and smoke evidence, but it
cannot issue commit-bound receipts or a JStack release-readiness result.

## Layout

- `mcp/jstack/jstack_mcp_server.py`: canonical MCP server.
- `mcp/jstack/audit/`: deterministic audit controls, evidence, findings, and
  output renderers.
- `mcp/jstack/loop/`: bounded contracts, private durable state, event chains,
  leases, convergence breakers, and terminal transitions.
- `mcp/jstack/program/`: generic phase DAGs, child proofs, intervention gates,
  active-time accounting, revisions, and finalization.
- `prompts/`: canonical slash-command prompts.
- `skills/jstack-dev/`, `skills/jstack-audit/`, and `skills/jstack-loop/`:
  canonical workflow skills.
- `mastery/`: engineering, audit, and loop training curricula.
- `plugin/`: generated umbrella plugin with portable Node/Python launcher.
- `plugins/`: five dedicated command plugins.
- `scripts/sync_artifacts.py`: generated-artifact and version enforcement.
- `scripts/install.py`: staged legacy direct installer.
- `tests/`: unit, transport, adversarial, release, mastery, and install tests.
- `jstack.enterprise.json`: this repository's policy.

## MCP Tools

Primary tools use the `jstack_*` prefix:

- runtime and binding: `runtime_status`, `detect_project`
- project and workflow: `plan`, `policy_check`,
  `preflight`, `health`, `review`
- teams: `team_plan`, `dispatch_check`
- evidence: `qa`, `security_audit`, `ship_check`,
  `release_readiness`
- audit: `audit`, `audit_finalize`
- loop: `loop_start`, `loop_status`, `loop_checkpoint`, `loop_revise`,
  `loop_stop`, `loop_finalize`
- program: `program_goal_readiness`, `program_start`, `program_status`,
  `program_next`, `program_phase_bind`, `program_phase_complete`,
  `program_gate_challenge`, `program_gate_resolve`,
  `program_evidence_register`, `program_pause`, `program_resume`,
  `program_revise`, `program_cancel`, `program_finalize`
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

Register the five directories under `plugins/` in a personal marketplace,
then install:

~~~text
codex plugin add j-stack-dev@personal
codex plugin add jstack-subagents@personal
codex plugin add jstack-full-team@personal
codex plugin add jstack-audit@personal
codex plugin add jstack-loop@personal
~~~

The umbrella `plugin/` is an alternative all-in-one distribution. Do not
install it alongside the five dedicated command plugins or the command palette
will contain duplicates.

Dedicated command plugins are skill-only surfaces and require the shared
`jstack` MCP installation. The umbrella plugin bundles that MCP itself.

Restart Codex or open a new task after plugin/MCP changes.

### Legacy Direct Install

~~~text
python scripts/install.py
~~~

This installs prompts, all three canonical skills, the MCP server, curricula, and MCP
configuration under `~/.codex` using a transaction-wide staged replacement. A
failure restores every affected target; the previous config is also retained as
a backup after a successful install.

## Mastery

Start the engineering track at Stage 0:

1. Call `jstack_mastery_start`.
2. Use `jstack_mastery_status` to select the next drill.
3. Complete the real task and required artifacts.
4. Gather commit-bound QA/security evidence.
5. Record independently cited assessment with `jstack_mastery_record`.

Read [the mastery system](docs/mastery-system.md) for stages, scoring,
advancement, and capstones. The profile is a local deliberate-practice record,
not an accredited credential.

Use `track="audit"` with the same mastery tools for the audit curriculum. See
[the audit system](docs/audit-system.md) and
[audit mastery](docs/audit-mastery-system.md).

Use `track="loop"` for goal-contract, convergence, orchestration, autonomy,
and loop-platform training. See [the loop system](docs/loop-system.md),
[loop mastery](docs/loop-mastery-system.md), and
[ADR 0002](docs/adr/0002-jstack-loop-protocol.md). The semantic intake and
confirmation boundary is specified in
[ADR 0003](docs/adr/0003-goal-readiness-gate.md).
Multi-phase operation is documented in [the program system](docs/program-system.md),
[ADR 0004](docs/adr/0004-program-orchestration-protocol.md), and the
[0.5 migration guide](docs/migration-0.5.md).

## Governance

See [architecture](ARCHITECTURE.md), [security](SECURITY.md),
[contributing](CONTRIBUTING.md), and [changelog](CHANGELOG.md).
