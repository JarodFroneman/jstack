# Migrating To JStack v0.10.0-alpha.6

JStack v0.10.0-alpha.6 implements Phase 5 of the verified Audit Mastery
roadmap: Performance and Resource-Efficiency Auditor. This remains a
prerelease. The new stage verifies signed measurements and one separately
authorized committed correction; it does not let Audit execute benchmarks,
optimize code, or certify production capacity.

## What Changed

- The Audit curriculum content version is now 7.
- Stage 5 uses closed performance-capture, results, and findings schemas.
- Its exact artifacts are `benchmark-plan.md`, `baseline-results.json`, and
  `performance-findings.json` beneath `.jstack-training/`.
- `jstack_performance_capture` is the 51st canonical MCP tool. It discovers
  existing project commands and, only in a separately authorized trusted
  development/QA workflow, captures bounded structured samples at an exact
  revision and project fingerprint.
- Capture receipts bind the Git tree, command fingerprint, closed workload,
  local environment, normalized samples, policy, tool version, and live server
  session. Receipts are passed directly through MCP; no approval token,
  signing key, challenge file, or terminal command is required.
- Workloads declare input identity, seed, concurrency, warmups, retained
  iterations, timeout, critical path, and realism rationale. Every capture has
  exactly one primary and at least one guardrail metric.
- JStack retains all samples and recomputes mean, nearest-rank percentiles,
  budget results, candidate improvement, and guardrail regressions. Hidden
  outlier removal and self-reported percentage claims fail closed.
- Both Stage 5 drills require current passing JStack QA. The implementation
  drill additionally requires a strict ancestor baseline, current committed
  candidate, exact Git diff, comparable signed captures, a met budget, positive
  improvement, and non-regressing guardrails.
- Stage 5 advancement requires three independent deterministic attempts across
  at least two commits, every score at least 80, a mean of at least 85, and
  both named drills.

## Safety Boundary

Audit itself never calls the performance runner or edits the target. Local
capture closes stdin, avoids a shell, scrubs inherited variables, forwards no
secrets, isolates HOME, bounds process output/time, writes to a fixed external
file, and rejects Git-visible tracked or non-ignored repository mutation. It
still has the current user's
filesystem and network privileges and is not an OS sandbox. Use an external
container or VM for untrusted code.

A signed capture proves binding and integrity for one bounded local run. It
does not prove workload realism, host isolation, measurement accuracy,
universal performance, production capacity, correctness, optimization safety,
release readiness, or production authority.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.6` tag.
2. Back up the installed MCP, five plugin sources/caches, Codex configuration,
   marketplace configuration, and `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run `python3 mcp/jstack/smoke_test.py`.
6. Install with `python3 scripts/install.py` or reinstall the five dedicated
   plugins and shared MCP using `docs/installation.md`.
7. Restart Codex and confirm the MCP and all five plugins report
   `0.10.0-alpha.6`, the MCP exposes 51 canonical tools including
   `jstack_performance_capture`, and the umbrella plugin remains absent in the
   dedicated layout.

Existing mastery profiles retain completed stages and attempt history. Earlier
attempt records keep their original curriculum digest; new Stage 5 attempts
bind curriculum version 7.

## Rollback

Restore the MCP directory, five plugin sources/caches, and Codex configuration
from the same pre-upgrade backup, then restart Codex and rerun the installed
smoke test. Preserve `~/.jstack` state unless a separate recovery procedure
requires otherwise.
