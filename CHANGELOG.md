# Changelog

## 0.5.0 - 2026-07-16

- Added a phase-count-agnostic Program -> Phase orchestration protocol above
  bounded JStack child loops for long, heterogeneous, or dependency-driven
  projects.
- Added 14 program MCP tools for exact readiness, durable start/status,
  conservative DAG scheduling, child binding/completion, human and external
  gates, pause/resume/revision/cancellation, and finalization.
- Added exact child-contract matching, durable loop completion attestations,
  declared-output hashing, transitive invalidation, baseline/policy/tool
  revalidation, and final release-audit/security/integrated-review floors.
- Added signed-local human identities with role and quorum checks, exact
  contract-bound approval challenges, an external operator signer, and
  freshness-aware external artifact evidence.
- Added active-work clocks that exclude human, external, and manual waits;
  approval-paused child loops release and explicitly reacquire write leases.
- Added transactional idempotency keys for every state-changing program call,
  hash-chained program events, versioned contracts, pending-write recovery, and
  private state outside the repository.
- Added active-budget freezing, orphaned-start reference recovery, history-wide
  start idempotency, scheduler-enforced binding, inherited blocked actions,
  revision-safe gate clearing, descriptor-safe evidence hashing, and repeatable
  completion revalidation.
- Published JSON Schemas for contracts, status, gates, and evidence plus
  enterprise policy/identity templates, ADR 0004, operator documentation, and
  a 0.5 migration/rollback guide.
- Updated `/jstack-loop` to choose one bounded loop or a project-derived
  multi-phase program and compose each phase with explicitly approved
  single-lead, specialist-team, or full-team delivery.
- Added variable-size, end-to-end child proof, human gate, external evidence,
  idempotency, active-time, lease, tamper, and program finalization coverage.

## 0.4.1 - 2026-07-15

- Added mandatory semantic goal readiness before loop start and material
  contract revision, including structured domain context, source attribution,
  assumptions, unresolved questions, and explicit inference tracking.
- Added adaptive intake with the complete gap set and at most three targeted
  questions per round, including niche requirements for product, security,
  financial/data, production, research, and unknown domains.
- Added exact-digest confirmation for ambiguous, inferred, assumption-bearing,
  sensitive-domain, medium-or-higher-risk, and L3 contracts.
- Added short-lived session-local readiness receipts bound to the exact semantic
  contract, Git fingerprint, policy, tool version, loop ID, and prior revision.
- Persisted additive goal context/readiness metadata while retaining read
  compatibility with 0.4.0 loop state and approval-only resume revisions.
- Added adversarial coverage for incomplete intake, stale confirmation,
  contract-mismatched receipts, material revisions, sensitive-domain questions,
  and unsafe repository context sources.

## 0.4.0 - 2026-07-15

- Added `/jstack-loop` as a fifth workflow that composes Codex Goal mode with
  an explicitly selected JStack single-lead, specialist-team, or full-team
  execution mode.
- Added six fail-closed loop MCP tools for start, status, checkpoint, contract
  revision, stop, and evidence-bound finalization.
- Added versioned Git-bound contracts, clean-start write controls, linked
  worktree attestation for L3, one active write lease, private atomic state,
  validated revision history, snapshot-bound SHA-256 hash-chained events, and
  interruption recovery.
- Added current QA, security, audit, deterministic review, artifact, and named
  approval criteria plus path, policy, protected-file, change-count, and
  no-op completion controls.
- Added iteration, elapsed-time, no-progress, repeated-failure, and oscillation
  circuit breakers without weakening Codex Goal complete/blocked semantics.
- Added the dedicated and umbrella loop skill/plugin surfaces, legacy installer
  support, architecture and operator documentation, and generated-artifact
  parity.
- Added a ten-stage loop-engineering mastery curriculum and atomic mastery
  profile v1/v2 to v3 migration while preserving engineering and audit state.
- Added signed Stage 9 loop capstone attestations, exact baseline ancestry,
  segment-aware scope globs, circuit-breaker resume approvals, hidden-index and
  unsafe Git path rejection, and policy/tool-version drift gates.
- Adapted loop/goal separation and staged-learning concepts from the Cobus
  Greyling reference repositories without adding an upstream runtime or copied
  source dependency.

## 0.3.1 - 2026-07-13

- Kept the umbrella plugin's default prompts within Codex's three-prompt
  manifest limit while retaining all four workflows in its description and
  dedicated plugin surfaces.

## 0.3.0 - 2026-07-13

- Added the read-only `/jstack-audit` workflow with quick, standard, deep, and
  release profiles.
- Added deterministic `jstack_audit` and `jstack_audit_finalize` MCP contracts,
  versioned findings/results, coverage matrices, Markdown summaries, and SARIF
  2.1.0 output with stable fingerprints.
- Added a versioned control catalogue, repository/path/limit/redaction
  hardening, curated analyzer discovery, and explicit suppression validation.
- Added session-local audit receipts while preserving the existing secret-scan
  receipt and release-readiness behavior; the audit release gate is opt-in.
- Added a separate ten-stage audit mastery curriculum and atomic profile v1 to
  v2 migration with engineering remaining the default track.
- Added umbrella, dedicated plugin, legacy installer, compatibility,
  adversarial, and seeded audit fixture coverage.
- Bound suppression expiry to server time and release-time revalidation, and
  made release receipts require complete repository and release-range scope.
- Made Quick execution impossible, failed adapters incomplete, Node launchers
  discovery-only until toolchain identity can be attested, and requested output
  formats transport-bounded.
- Made Stage 9 blindness depend on runtime-keyed independent assessor
  attestations for two distinct challenge subjects; the bundled answer key is
  explicitly a transparent practice benchmark.
- Added transaction-wide installer rollback and exact generated-tree inventory
  checks that reject stale packaged files without rewriting unrelated files.

## 0.2.1 - 2026-07-10

- Added `jstack_runtime_status` so clients can prove MCP mount state without a
  Git repository.
- Added explicit `git` and `artifact-only` project bindings for detection and
  planning.
- Added artifact-only evidence requirements for hashes, tests, backups,
  immutable runtime identity, rollback, monitoring, and smoke checks.
- Kept policy, preflight, review, QA, security receipts, context receipts,
  mastery records, quant review, and release readiness fail-closed on non-Git
  directories.
- Updated all command surfaces to distinguish MCP availability from Git project
  eligibility and stop misreporting Git rejection as an attachment failure.

## 0.2.0 - 2026-07-10

- Replaced incompatible Content-Length framing with MCP JSONL stdio transport.
- Made command mode authoritative for single-lead, smart-subagents, and
  full-team workflows.
- Added non-overridable policy floors and complete committed/worktree change
  evidence.
- Added explicit-trust QA execution with scrubbed environment, isolated home,
  mutation detection, and signed evidence receipts.
- Bound release readiness to an explicit base, clean commit, policy digest,
  exact command receipts, complete security scan, approval reference, rollback,
  and monitoring.
- Hardened secret scanning for dotfiles, symlinks, truncation, source previews,
  and secrets added then deleted inside a release range.
- Added dispatch role, packet, permission, containment, and semantic overlap
  validation.
- Added a ten-stage evidence-backed mastery curriculum with local progression
  records and assistance caps.
- Added deterministic artifact synchronization, portable plugin launch,
  staged installers, adversarial tests, and cross-platform CI.
