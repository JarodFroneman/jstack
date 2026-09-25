# Migrating to JStack 0.13.1

JStack `0.13.1` updates the existing Product UI skill with optional Liquid
Glass guidance and an explicit design-only handoff to GStack workflows.

## Behavior

- Request Liquid Glass, or extend an existing product using that material,
  to load the new reference. Ordinary UI work keeps its existing profile and
  design-system precedence.
- Native Apple work uses current HIG/framework guidance and checks SDK/OS
  availability. Web work uses accessible Apple-inspired materials with tested
  browser fallbacks. Community references are optional and are not installed.
- When GStack leads implementation or deployment, Product UI contributes
  design and verification guidance. GStack owns execution, evidence, review,
  and approvals. No JStack receipt is required by this design-only handoff.
- JStack-led workflows retain their existing UI contracts and finalization.

For example: "Use GStack implementation with JStack Product UI design
guidance and preserve the existing Liquid Glass system." Invoke the selected
deployment workflow when the implementation is ready and deployment is approved.

## Upgrade and verification

1. Preserve the current `0.13.0` plugin sources, caches, shared MCP,
   marketplace metadata, and Codex configuration as one rollback unit.
2. Use the exact annotated `v0.13.1` release tag and the existing
   [installation layout](installation.md). Do not combine dedicated plugins
   with an umbrella or duplicate direct skill installation.
3. Verify generated artifact parity, contract compatibility, product
   boundaries, the Proof Plane corpus lock, compilation, the complete test
   suite, and the MCP smoke test before activation. Set Python's
   `PYTHONPYCACHEPREFIX` to a directory outside the checkout when compiling;
   the reviewed Proof Plane fixtures reject extra bytecode files.
4. Confirm all seven plugins and the shared MCP report `0.13.1`, with 65
   canonical tools and 52 frozen aliases, and one active Product UI skill.
   Its packaged `references/liquid-glass.md` must match the release source.
5. Start a fresh Codex task or restart Codex to discover the upgraded skills.

No project data, JStack state, provider runtime, API, or schema migration is
required. Preserve `~/.jstack` and the existing Graphify installation.
Receipts tied to a replaced server version/session must be issued normally
when using JStack-led workflows.

## Rollback

Reactivate the complete preserved `0.13.0` plugin/marketplace/MCP configuration,
restart Codex, and verify its installed bytes and smoke test. Preserve current
JStack project state and other Codex configuration. Never mix versions by
restoring only individual skill or runtime files.

The release provides design instructions, not an automatic visual-quality
guarantee or a bundled native/web rendering engine. Actual application
changes still require platform-specific runtime and accessibility checks.
