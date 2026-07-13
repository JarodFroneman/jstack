# Changelog

## 0.3.0 - Unreleased

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
