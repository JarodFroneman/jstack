# Changelog

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
