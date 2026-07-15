# JStack Architecture

## Authority

Canonical sources live in:

- `mcp/jstack/jstack_mcp_server.py`
- `mcp/jstack/audit/`
- `mcp/jstack/loop/`
- `mcp/jstack/schemas/`
- `prompts/`
- `skills/jstack-dev/`, `skills/jstack-audit/`, and `skills/jstack-loop/`
- the engineering, audit, and loop curricula under `mastery/`
- `mcp/jstack/templates/`

`scripts/sync_artifacts.py` generates and verifies plugin copies. It operates
only on Git-tracked and explicitly declared files, compares exact generated
tree inventories, and rejects drift, stale generated files, BOMs, malformed
JSON, and version mismatch.

## Control Plane

The MCP server uses newline-delimited JSON-RPC over stdio. It contains:

- command/risk routing and enterprise gates
- project and policy inspection
- team planning and coordination validation
- QA command discovery and explicitly approved execution
- current-tree and release-range secret scanning
- deterministic audit collection and evidence-bound finalization
- semantic goal-readiness assessment and Git-bound start/revision receipts
- durable bounded loop contracts, checkpoints, convergence breakers, and
  evidence-bound finalization
- commit-bound HMAC evidence receipts
- release readiness evaluation
- local context and mastery records

The MCP never spawns platform subagents or performs a deployment. Codex's
platform tools perform real agent dispatch. Project-specific release tools
perform real production mutation only after separate authorization.

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

Write loops require a clean start and an exclusive repository lease. L3 also
requires a linked worktree, low risk, bounded paths, and QA, security, audit,
and review criteria. Contract revisions reset completion evidence. Completion
never implies release authorization.

The lease is per resolved Git checkout, so explicitly isolated linked
worktrees can operate independently. The original commit remains the exact
merge-base boundary. Contract history, the current snapshot, and every event
head are mutually digest-bound; a pending transaction journal replays an
interrupted multi-file commit.

## Audit Protocol

`jstack_audit` creates a state-bound coverage contract and signed audit session.
`jstack_audit_finalize` validates repository-relative evidence, coverage,
findings, suppressions, and current state before deriving a result and, for Git
projects, issuing an audit receipt. The deterministic MCP validates evidence; it
does not claim to perform semantic model reasoning.

The audit command uses a two-pass agent boundary: candidate generation followed
by challenge and verification. Artifact-only audits are advisory and cannot
issue a Git-bound receipt or a formal release-ready result.

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
suppression expiries. Release-profile receipts bind complete repository scope
and the release-range digest. The audit release gate is opt-in; QA and security
receipt compatibility is unchanged.

QA discovery is not evidence. A complete clean scan is evidence only for the
heuristics it actually ran. Missing, stale, failed, timed-out, truncated, or
inconclusive evidence never becomes a pass.

Loop completion receipts additionally bind the loop ID, contract digest,
baseline commit, completion-evidence digest, event-chain head, execution mode,
autonomy, and risk tier. Durable state survives MCP restarts, but signed
receipts remain intentionally session-local and must be revalidated.

## Security Boundary

Git inspection neutralizes common external diff, prompt, fsmonitor, and global
configuration hooks. Scanner files are opened descriptor-first without
following symlinks where the host supports `O_NOFOLLOW`.

The Python QA runner is not an operating-system sandbox. It closes stdin,
scrubs inherited variables, isolates HOME, avoids a shell, caps output/time, and
kills its process group. Untrusted project execution still requires a
container, VM, or host sandbox.

The same boundary applies to approved audit adapters. Static audit collection
does not execute repository code or perform network work. Adapter offline flags
are advisory process configuration; they do not remove host filesystem or
network privileges. Quick therefore rejects all adapter execution, and
untrusted verification requires an externally enforced read-only sandbox.
