# Migrating To JStack v0.10.0-alpha.5

JStack v0.10.0-alpha.5 implements Phase 4 of the verified Audit Mastery
roadmap: Maintainability and Architecture Auditor. This remains a prerelease.
The new stage validates architecture evidence and one separately authorized
committed remediation; it does not let Audit edit code or certify an
architecture as production-ready.

## What Changed

- The Audit curriculum content version is now 6.
- Stage 4 uses the closed `jstack.audit.maintainability-report.v1` schema.
- Its exact artifacts are `architecture-map.md`,
  `maintainability-report.json`, and `migration-outline.md` beneath
  `.jstack-training/`.
- The report binds exact baseline/candidate Git commits and trees plus both
  narrative hashes. Citations identify their revision and are verified against
  immutable Git objects.
- Exactly six surfaces must be classified: module boundaries, dependency
  direction, contracts and compatibility, change amplification, testability,
  and migration risk.
- Components, dependencies, contracts, change scenarios, material non-style
  findings, remediations, and compatibility assessments use closed reciprocal
  references. Unsupported coverage, gaps, stale or unused evidence, malformed
  graphs, and speculative high severity fail closed.
- The architecture drill is static and permits proposals only. The remediation
  drill verifies one candidate already changed and committed through a
  separately authorized development workflow.
- Remediation verification requires a strict ancestor baseline, exact Git-diff
  reconciliation, one resolved finding and implemented remediation, supported
  baseline/candidate compatibility, and a current passing exact-candidate
  JStack QA receipt.
- Stage 4 advancement requires three independent deterministic attempts across
  at least two commits, every score at least 80, a mean of at least 85, and
  both named drills.
- The MCP tool inventory remains 50 and no new top-level command is added.

## Safety Boundary

Stage 4 treats repository content as untrusted data. Its evaluator reads Git
objects and existing receipts but executes no repository code, accesses no
network or secrets, edits no application code, and grants no Git, publication,
release, deployment, or production authority. JStack QA is environment
hardening rather than an OS or network sandbox.

A pass proves only that the submitted package met JStack's deterministic
structure, binding, traceability, diff, compatibility, receipt, and safety
contract. It does not prove semantic correctness, behavior preservation,
architecture quality, compatibility, vulnerability absence, remediation
safety, release readiness, or production security.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.5` tag.
2. Back up the installed MCP, five plugin sources/caches, Codex configuration,
   marketplace configuration, and `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run `python3 mcp/jstack/smoke_test.py`.
6. Install with `python3 scripts/install.py` or reinstall the five dedicated
   plugins and shared MCP using `docs/installation.md`.
7. Restart Codex and confirm the MCP and all five plugins report
   `0.10.0-alpha.5`, the MCP exposes 50 canonical tools, and the umbrella
   plugin remains absent in the dedicated layout.

Existing mastery profiles migrate without resetting completed stages or
attempt history. Earlier attempt records keep their original curriculum
digest; new Stage 4 attempts bind curriculum version 6.

## Rollback

Restore the MCP directory, five plugin sources/caches, and Codex configuration
from the same pre-upgrade backup, then restart Codex and rerun the installed
smoke test. Preserve `~/.jstack` state unless a separate recovery procedure
requires otherwise.
