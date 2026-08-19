# Migrating To JStack v0.10.0-beta.3

## Release Boundary

`v0.10.0-beta.3` is the Evidence Builder prerelease. It adds a sixth explicit
Codex workflow for turning user-provided screenshots, Figma exports, and exact
approved URL captures into a private, digest-bound reference bundle before UI
implementation.

This remains an unvalidated prerelease. It does not complete or replace the
deferred Beta.1 Proof Study, and it makes no stable-release, measured-uplift,
universal-quality, legal, security-certification, or production-readiness
claim.

## Public Surface Changes

- Dedicated command plugins increase from five to six with
  `jstack-evidence-builder`.
- Canonical MCP tools increase from 54 to 56 with
  `jstack_ui_reference_contract` and `jstack_ui_reference_finalize`.
- All 52 legacy `gstack_*` aliases remain frozen and unchanged. No reference or
  Product Interface aliases are added.
- Ordinary Product Interface contracts remain byte-compatible
  `jstack.ui.contract.v1`. Attaching a finalized reference receipt produces the
  additive closed `jstack.ui.contract.v2` successor.

## Evidence Builder Workflow

1. Invoke `/jstack-evidence-builder` with attached screenshots or Figma exports,
   or with exact URLs that the user has approved for host-browser capture.
2. Declare viewport coverage, rights basis, sensitive-data treatment, and any
   external model-provider processing before bytes leave the host.
3. Build a private bundle under the server-selected JStack evidence root.
4. Finalize the bundle with `jstack_ui_reference_finalize`.
5. Optionally pass the resulting reference receipt to `jstack_ui_contract` for
   the later implementation phase.

Reference inputs never satisfy candidate screenshot, accessibility, objective
result, Product observation, QA, security, launch, or release requirements.
They remain inspiration and implementation context only.

The v1 prototype boundary is deliberately narrow: analysis-only is the
default; optional output is at most two isolated static HTML/CSS or
HTML/Tailwind variants with network access disabled. React, Vue, Bootstrap,
Ionic, video, Replicate, and embedded screenshot-to-code runtime integration
remain deferred.

## Compatibility And Dependencies

- Python 3.9+ and the standard-library core remain supported.
- The release vendors no screenshot-to-code runtime, prompt, provider SDK, or
  network service. `abi/screenshot-to-code` is a pinned MIT-licensed design
  reference only.
- Existing callers using the 52 legacy aliases continue to receive their
  frozen names and request schemas.
- Existing reference-free UI contract consumers continue to receive v1.

## Upgrade

1. Stop or drain active Codex/plugin processes before replacing a shared
   in-place installation, or use a versioned side-by-side Layout B rollout.
2. Retain the complete Beta.2 MCP, plugin-source, plugin-cache, marketplace,
   configuration, and state inventory as the rollback unit.
3. Check out the exact annotated `v0.10.0-beta.3` tag and verify the GitHub
   release is marked as a prerelease.
4. Run artifact synchronization, the test suite, contract compatibility,
   product-boundary validation, and MCP smoke checks before installation.
5. Install all six dedicated plugins at the same version and point the shared
   MCP configuration at the matching Beta.3 server.
6. Keep the umbrella plugin uninstalled when using the dedicated layout.
7. Restart Codex or open a fresh task, then verify six enabled command plugins,
   MCP version `0.10.0-beta.3`, 56 canonical tools, 52 aliases, and exact
   source/cache parity.

## Rollback

Restore the complete Beta.2 unit rather than mixing Beta.2 and Beta.3 MCP,
plugin sources, caches, or marketplace pointers. Preserve `~/.jstack` loop,
program, mastery, and evidence state unless a separately reviewed migration
requires otherwise. Restart Codex and rerun the installed MCP smoke test after
rollback.
