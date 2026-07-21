# JStack Architecture

## Authority

Canonical sources live in:

- `mcp/jstack/jstack_mcp_server.py`
- `mcp/jstack/capabilities/`
- `mcp/jstack/audit/`
- `mcp/jstack/authorization/`
- `mcp/jstack/loop/`
- `mcp/jstack/program/`
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
- deterministic role-bound capability routing and specialist handoff validation
- QA command discovery and explicitly approved execution
- current-tree and release-range secret scanning
- deterministic audit collection and evidence-bound finalization
- semantic goal-readiness assessment and Git-bound start/revision receipts
- durable bounded loop contracts, checkpoints, convergence breakers, and
  evidence-bound finalization
- durable Program -> Phase DAGs, intervention gates, child proofs, and final
  integration acceptance
- signed exact external-action challenges, durable one-time consumption, and
  short-lived execution permits
- commit-bound HMAC evidence receipts
- release readiness evaluation
- local context and mastery records

The MCP never spawns platform subagents and never performs repository, Git,
provider, deployment, or production actions. Codex's platform tools perform
real dispatch and action execution only after the applicable JStack boundary.

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

Human decisions use signed configured identities, role coverage, quorum, and
freshness. External gates use bounded hashed artifacts and provenance.
Waiting states pause active program time. Revisions invalidate changed phases
and all transitive dependants while preserving unaffected current proof.

State-changing program calls use transaction-bound idempotency keys. Program
contracts, snapshots, events, operation records, and pending transactions live
under `~/.jstack/programs` and fail closed on integrity drift. The live program
manifest never mounts into the Git repository.

## External-Action Authorization Protocol

Every project defaults to local-only. Eleven separately named actions cover
repository creation, remote add/change, commit, push, pull-request creation,
merge, tag creation, release creation, deployment, and production mutation.
One challenge can contain exactly one action.

The challenge binds exact provider, owner, repository, visibility, remote,
branch, tag, commit, and environment fields to the absolute project, complete
workspace fingerprint, policy, current HEAD, attached branch, remote snapshot,
tool version, and MCP session. A configured identity holding the action's exact
role signs the canonical challenge outside Codex. The server verifies the
signature and unchanged subject before issuing an unconsumed authorization.

Immediately before execution, the caller supplies a fresh provider observation
of the same exact target. Destructive consumption revalidates every binding and
returns a permit valid for at most 60 seconds. Authorization state is private
and session-sealed under `~/.jstack/external-actions`. In-process consumption
memory plus sealed state rejects same-session rollback and replay; MCP restart
invalidates every prior receipt.

The protocol grants no arbitrary execution capability. The external executor
must perform one exact operation at most once, and command contracts forbid
bypassing the permit through shell, Git, provider, browser, CI/CD, deployment,
or production tools. This is a mandatory JStack workflow boundary, not an
operating-system interceptor.

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
capability IDs. Release-profile receipts bind complete repository scope and the
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

External-action authorization receipts additionally bind one action, the exact
target and required role, challenge and attestation digests, current project
subject, policy, tool version, and session. Consumption records bind a unique
operation ID and fresh provider-observation digest. A permit is never a result
receipt and cannot be reused, retried, widened, or promoted to another action.

## Security Boundary

Git inspection neutralizes common external diff, prompt, fsmonitor, and global
configuration hooks. Scanner files are opened descriptor-first without
following symlinks where the host supports `O_NOFOLLOW`.

The Python QA runner is not an operating-system sandbox. It closes stdin,
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

The signed-local program identity provider uses environment-held HMAC keys.
It proves shared-key possession and configured role only; it is not SSO or
non-repudiation. Codex prepares and verifies challenges but must not sign on a
human approver's behalf.

The external-action signer has the same same-account/shared-key limitation and
adds mandatory full challenge-digest confirmation. It prevents broad intent
from being converted into a compliant JStack permit, but provider protections,
least-privilege credentials, host tool restrictions, and an OS sandbox remain
necessary against a malicious executor or account compromise.
