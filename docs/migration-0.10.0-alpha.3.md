# Migrating To JStack v0.10.0-alpha.3

JStack v0.10.0-alpha.3 implements Phase 2 of the planned verified
security-remediation foundation: Correctness and Reliability Auditor. It
remains a prerelease. Stage 2 verifies an evidence package; it does not patch
code, prove vulnerability absence, detect every zero-day, certify production,
or authorize deployment.

## What Changes

- Audit curriculum content version advances from 3 to 4.
- Audit mastery Stage 2 validates `correctness-report.json` and
  `reproductions/manifest.json` against the closed
  `jstack.audit.correctness-report.v1` and
  `jstack.audit.correctness-reproductions.v1` contracts.
- Stage 2 covers exactly logic, state transitions, error handling, and
  reliability against the current committed Git HEAD and tree.
- Material claims cite tracked regular source files by line range and current
  SHA-256. The report is also bound to the exact reproduction manifest digest.
- Blocker and high/critical claims require verified, high-confidence,
  reachable or conditional evidence linked to violated invariants and
  reciprocal reproductions. Speculative high severity fails closed.
- Static invariant proofs avoid execution. Executed reproductions require a
  passing current exact-revision JStack QA receipt with matching command key,
  fingerprint, profile, and return code.
- Every verified finding requires a complete before-fix, after-fix,
  unrelated-behavior, and failure-state regression plan.
- Two consecutive independent deterministic passes scoring at least 80 are
  required to advance from Stage 2.

## What Does Not Change

- The five JStack commands and 50 canonical MCP tools are unchanged.
- Audit sessions remain read-only. Only an explicitly requested mastery
  assessment may create declared training artifacts under `.jstack-training/`.
- Mastery profile schema remains `jstack.mastery.profile.v3`; existing
  engineering, audit, and loop state is retained.
- No JStack challenge, approval token, signer, mailbox, or terminal-paste flow
  is introduced.
- Python 3.9+, Codex packaging, Claude MCP preview, and macOS/Linux/Windows
  support remain unchanged.

## Stage 2 Artifact Contract

Create only these exact paths under `.jstack-training/`:

- `correctness-report.json`
- `invariants.md`
- `reproductions/manifest.json`

Build the JSON documents from the published schemas under
`mcp/jstack/schemas/`. Use the current committed `git rev-parse HEAD` and
`git rev-parse HEAD^{tree}` values. Do not retain command output in the
reproduction directory. Any non-training dirty path, unsupported surface,
unresolved gap, stale binding, unsafe or unused citation, unverified strong
claim, mismatched reproduction, incomplete regression plan, or secret-like
value makes the attempt ineligible.

Prefer a `static-invariant` reproduction when source evidence proves the
counterexample. If execution is necessary, run only a discovered JStack QA
command within explicit user scope and bind its current passing receipt. The
scrubbed environment and isolated HOME are not OS or network isolation; use a
container or VM for untrusted repositories.

## Upgrade And Verify

1. Check out the immutable `v0.10.0-alpha.3` tag.
2. Back up the current MCP payload, plugin sources and caches, Codex
   configuration, and `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run `python3 mcp/jstack/smoke_test.py`.
6. Run `python3 scripts/install.py`, reinstall the selected dedicated plugins,
   and restart Codex or open a new task.
7. Confirm the MCP reports `0.10.0-alpha.3`, all five installed plugins report
   the same release/cachebuster, and the canonical tool count remains 50.

## Rollback

Restore the complete v0.10.0-alpha.2 MCP and plugin release unit from backup or
the immutable tag, restart Codex, and rerun the smoke test. Preserve
`~/.jstack/mastery/profile.json`; v0.10.0-alpha.2 can load profile v3, although
it does not enforce the Stage 2 correctness evaluator.
