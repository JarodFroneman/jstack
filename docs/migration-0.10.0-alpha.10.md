# Migrating To JStack v0.10.0-alpha.10

JStack v0.10.0-alpha.10 adds the development-only Proof Foundation. The
installed JStack workflows and MCP contracts remain unchanged.

## What Changed

- `evals/` now contains closed corpus, task, run, blinded-review, and score
  contracts plus a deterministic standard-library mock runner and scorer.
- The public development manifest declares TypeScript/web, Python API,
  Java/C#, C/C++, data/database, and legacy-repository families, with one
  seeded-defect, one historical-replay, and one clean-control slot planned for
  each family.
- Corpus manifests now carry a closed execution plan. Scoring requires an
  exact match to every expected run and binds the manifest, run, and review
  digests; public plans also require the complete 18-slot corpus, both modes,
  paired conditions, and at least three repetitions.
- CI now verifies the Proof Plane content lock, alpha.9 public-contract
  compatibility, and the permanent product boundary.
- Direct and umbrella installs use a 1,900-second MCP transport window so the
  longest permitted 1,800-second capture has bounded receipt overhead, without
  relaxing any workflow-level command budget.
- The release checklist no longer contains retired challenge, signer, token,
  permit, expiry, or terminal-paste fields.

## Evidence Boundary

The Proof Plane is not installed into Codex. It does not execute a repository,
download benchmark source, call Codex or Claude, invoke a scanner, access a
network, contain a holdout answer, or upload pilot data. Its mock score is a
golden protocol test only.

The development manifest has no runnable task files and all marketing claim
flags are false. Real-project results, host-model comparisons, JStack uplift,
and novel logic-flaw claims remain unavailable until later benchmark and pilot
milestones produce independently reviewed evidence.

The mock run additionally verifies equal controlled time, token, cost,
allowed-tool, and tool-call limits; exact host/model/JStack/image/toolchain
bindings; conservative paired intervals; and fail-closed reviewer agreement.

## Compatibility

- The five public commands are unchanged.
- The MCP still exposes 52 canonical `jstack_*` tools and 52 legacy
  `gstack_*` aliases. Every alpha.9 request-schema digest remains unchanged.
- All published core v1 schema bytes and MCP protocol versions are unchanged.
- The 11 roles, 18 capability packs, 47 launch controls, 22 launch surfaces,
  mastery profile v3, loop/program state markers, and policy v1 marker are
  unchanged.
- Python 3.9+ and the standard-library-only installed runtime remain supported.
- No durable-state migration is required.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.10` tag.
2. Back up the current MCP, plugin sources/caches, Codex configuration, and
   `~/.jstack` state.
3. Run:

   ```text
   python3 scripts/sync_artifacts.py --check
   python3 scripts/check_contract_compatibility.py
   python3 scripts/check_product_boundaries.py
   python3 -m evals.runner.cli verify-lock
   python3 -m unittest discover -s tests -v
   python3 mcp/jstack/smoke_test.py
   ```

4. Run `python3 scripts/install.py` for the shared Codex installation or
   reinstall the five dedicated plugins from the personal marketplace.
5. Restart Codex or open a new task.
6. Verify the MCP initialize response reports `0.10.0-alpha.10`, `tools/list`
   exposes 52 canonical tools, all five dedicated plugins report the same
   version, and the umbrella plugin remains uninstalled when using the
   dedicated layout.

## Rollback

Restore the complete v0.10.0-alpha.9 MCP and plugin release unit from backup or
the immutable `v0.10.0-alpha.9` tag, then restart Codex and rerun the installed
MCP smoke test. Preserve `~/.jstack` state; alpha.10 changes no persisted-state
schema. The development-only `evals/` directory has no installed rollback
surface.

## Meaning Of A Pass

An alpha.10 pass proves deterministic contract validation, content integrity,
mock scoring, compatibility with the frozen alpha.9 public surface, and the
anti-bloat packaging boundary. It does not prove real-project task completion,
vulnerability absence, safe patching, host superiority, production incident
prevention, universal zero-day detection, professional-grade code, release
authorization, or production readiness.
