# Migrating To JStack v0.10.0-alpha.7

JStack v0.10.0-alpha.7 implements Phase 6 of the verified Audit Mastery
roadmap: Supply-Chain, Build and Release-Integrity Auditor. This remains a
prerelease. The stage verifies exact tracked inputs, CI controls, build traces,
provenance, generated artifacts, signed dependency-scanner evidence, and one
separately authorized committed hardening; it does not let Audit modify a
repository or certify vulnerability absence.

## What Changed

- The Audit curriculum content version is now 8.
- Stage 6 uses closed `jstack.audit.dependency-inventory.v1` and
  `jstack.audit.supply-chain-report.v1` schemas.
- Its exact artifacts are `dependency-inventory.json`, `build-trace.md`, and
  `supply-chain-report.json` beneath `.jstack-training/`.
- JStack independently enumerates and hashes tracked dependency/build inputs
  at exact baseline and candidate Git trees. Omitted or invented inventory
  entries fail closed.
- The static classifier covers the major language ecosystems and conventional
  build, provenance, CI, and generated-artifact paths. This is bounded
  structural discovery, not complete semantic package resolution.
- GitHub Actions references and top-level permissions are parsed from immutable
  Git blobs. Dynamic/unparseable references fail; mutable references and
  implicit, unsupported, or unbounded permissions require verified findings.
- Build graphs must trace source, configuration, or dependency materials to
  every candidate artifact. Every candidate artifact needs explicit
  provenance status, and every conventionally discovered generated artifact
  must disclose exact-copy, drift, or unverifiable status.
- Final audit receipts now retain bounded sanitized adapter-result metadata.
  Stage 6 requires a current complete receipt with a passed no-mutation curated
  `dependency-analysis` result and `supply-chain` coverage. No scanner output
  or secret value is stored.
- A curated `osv-scanner-offline` adapter supplies optional cross-ecosystem
  advisory coverage. It requires the `osv-scanner` executable and
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` to identify an existing local
  database directory outside the audited repository. JStack binds the
  resolved executable identity, database path, fixed offline command, and
  result into the exact approval subject and receipt.
- Both drills require a current passing receipt for every discovered JStack QA
  command. The implementation drill additionally requires a strict ancestor,
  current committed candidate, exact changed-path set, and exactly one
  resolved/implemented control.
- Stage 6 advancement requires three independent deterministic attempts across
  at least two commits, every score at least 80, a mean of at least 85, and
  both named drills.

No new MCP tool is added. The canonical count remains 51, and receipts continue
to pass directly between tools without approval tokens, signing commands, or
terminal-paste ceremonies.

## Safety Boundary

The Stage 6 evaluator reads immutable Git blobs and existing receipts. It does
not execute repository code, resolve dependencies, contact package registries,
access secrets, or perform hardening. Curated scanner execution remains a
separately approved audit-adapter action, and the local runner is not an OS or
network sandbox. Use an external container or VM for untrusted repositories.

A Stage 6 pass proves bounded protocol integrity only. It does not prove full
transitive dependency semantics, complete/current advisory coverage,
reproducible builds, artifact authenticity outside the submitted evidence,
vulnerability absence, release readiness, or production authority.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.7` tag.
2. Back up the installed MCP, five plugin sources/caches, Codex configuration,
   marketplace configuration, and `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run `python3 mcp/jstack/smoke_test.py`.
6. For cross-ecosystem Stage 6 advisory evidence, install OSV-Scanner, prepare
   its offline database, and expose the external database directory to the
   JStack MCP process with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`.
7. Install with `python3 scripts/install.py` or reinstall the five dedicated
   plugins and shared MCP using `docs/installation.md`.
8. Restart Codex and confirm the MCP and all five plugins report
   `0.10.0-alpha.7`, the MCP still exposes 51 canonical tools, and the umbrella
   plugin remains absent in the dedicated layout.

Existing mastery profiles retain completed stages and attempt history. Earlier
attempt records keep their original curriculum digest; new Stage 6 attempts
bind curriculum version 8.

## Rollback

Restore the MCP directory, five plugin sources/caches, and Codex configuration
from the same pre-upgrade backup, then restart Codex and rerun the installed
smoke test. Preserve `~/.jstack` state unless a separate recovery procedure
requires otherwise.
