# Migrating To JStack v0.10.0-alpha.2

JStack v0.10.0-alpha.2 implements Phase 1 of the planned verified
security-remediation foundation: Repository Reconnaissance and System Mapping.
It remains a prerelease. Stage 1 is static comprehension and evidence binding,
not vulnerability scanning, zero-day detection, exploitation, patching, or
production remediation.

## What Changes

- Audit curriculum content version advances from 2 to 3.
- Audit mastery Stage 1 now validates `coverage-matrix.json` against the closed
  `jstack.audit.repository-map.v1` contract.
- Stage 1 maps exactly eight surfaces: architecture, entry points, data flows,
  trust boundaries, tests, dependencies, build/release, and generated
  artifacts.
- Every material map object must cite a tracked regular source file by line
  range and current SHA-256.
- Node, flow, and trust-boundary references, generated-artifact source
  provenance and drift risk, explicit gaps, exact limitations, Git HEAD/tree
  binding, and completeness are evaluated deterministically.
- Two consecutive independent deterministic passes scoring at least 80 are
  required to advance from Stage 1.

## What Does Not Change

- The five JStack commands and 50 canonical MCP tools are unchanged.
- Audit sessions remain read-only. Only an explicitly requested mastery
  assessment may create declared training artifacts beneath
  `.jstack-training/`.
- Mastery profile schema remains `jstack.mastery.profile.v3`; existing Stage 0
  completion and other track state are retained.
- No JStack challenge, approval token, signer, mailbox, or terminal-paste flow
  is introduced.
- Python 3.9+, Codex packaging, Claude MCP preview, and macOS/Linux/Windows
  support remain unchanged.

## Stage 1 Artifact Contract

Create these files only under `.jstack-training/`:

- `system-map.md`
- `trust-boundaries.md`
- `coverage-matrix.json`

Build the JSON document from the published schema at
`mcp/jstack/schemas/audit-repository-map.v1.schema.json`. Use the current
committed `git rev-parse HEAD` and `git rev-parse HEAD^{tree}` values. Do not
execute repository code to discover the map. Any non-training dirty path,
unsupported surface, unresolved gap, stale hash, unsafe citation, unused
evidence record, or invalid graph reference makes the attempt ineligible.

The full project fingerprint is still captured in the mastery attempt. It is
not embedded in the map because it includes the map artifact itself; the
immutable Git tree is the non-self-referential source subject.

## Upgrade And Verify

1. Check out the immutable `v0.10.0-alpha.2` tag.
2. Back up the current MCP payload, plugin sources and caches, Codex
   configuration, and `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run `python3 mcp/jstack/smoke_test.py`.
6. Run `python3 scripts/install.py`, reinstall the selected dedicated plugins,
   and restart Codex or open a new task.
7. Confirm the MCP reports `0.10.0-alpha.2`, all five installed plugins report
   the same release/cachebuster, and the canonical tool count remains 50.

## Rollback

Restore the complete v0.10.0-alpha.1 MCP and plugin release unit from backup or
the immutable tag, then restart Codex and rerun the smoke test. Preserve
`~/.jstack/mastery/profile.json`; v0.10.0-alpha.1 can load profile v3, although
it does not enforce the new Stage 1 evaluator.
