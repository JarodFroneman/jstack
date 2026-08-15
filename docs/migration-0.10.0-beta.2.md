# Migrating To JStack v0.10.0-beta.2

## Status

`v0.10.0-beta.2` is the Product Interface prerelease. It adds an original,
automatic design-and-evidence system to the five existing JStack workflows.
It remains a prerelease: publication, installation, deterministic tests, and
Product Interface receipts are not a stable-release or production-readiness
claim.

The separate Beta.1 Proof Study is still unvalidated. Its descriptors and
installable-product assets remain byte-frozen against the exact annotated
`v0.10.0-beta.1` tag and its 52-tool server. Beta.2 does not reopen, migrate,
complete, or substitute evidence for the deferred 18-image, 216-attempt,
432-review study.

## What Changes

- Every installable version-bearing artifact advances to `0.10.0-beta.2`.
- The command surface remains exactly five slash commands. Product Interface
  design is an automatically triggered skill, not a sixth command.
- The live MCP surface grows from 52 to 54 canonical `jstack_*` tools with
  `jstack_ui_contract` and `jstack_ui_finalize`.
- The compatibility surface remains exactly 52 legacy `gstack_*` aliases.
  The new UI tools intentionally have no legacy aliases.
- Product Interface applicability and receipts propagate through normal plans,
  team plans, bounded loops, multi-phase programs, and release readiness.
  JStack Audit applies the same catalog as read-only review criteria without
  issuing or finalizing a UI contract and without substituting for audit proof.
- Specialist result and handoff calls should pass the routed capability plan's
  exact `selectionDigest` as `capability_selection_digest`; it is required to
  disambiguate Product Interface routing when a generic or full-team goal uses
  the same role IDs as an ordinary plan.
- The separate UI catalog, contract, evidence, objective-result, structured
  Product-observation, and finalization schemas are installed with the MCP
  payload.

## Automatic Design Behavior

The `product-ui-design` skill activates when the request or changed paths
contain a user-facing interface. Backend-only or non-interface work does not
activate it. Ambiguous repository hints require review rather than silently
turning a backend task into a redesign.

Design decisions resolve in this order:

1. explicit user instructions;
2. the repository's existing design system, tokens, components, layouts,
   accessibility rules, and brand rules;
3. the applicable domain profile;
4. the `editorial-calm` fallback.

`editorial-calm` is the default for content, settings, account, research,
administrative, and workflow surfaces. `creative-canvas` is intended for
visual creation, media, spatial, node, timeline, and similar workspaces. A
hybrid product uses a calm shell around the creative workspace instead of
forcing one treatment everywhere.

Greenfield interfaces cover light and dark themes. Existing products preserve
their supported theme contract unless the user explicitly changes it. Shared
defaults use a 4px spacing base, restrained 4/8/12px radii, 1px separators,
zero negative letter spacing, 120/180/240ms purposeful motion, native platform
semantics, and reduced-motion/accessibility behavior. The skill avoids
gratuitous cards, nested cards, excessive pills, decorative gradient/orb
backgrounds, oversized headings, glassmorphism, and undifferentiated
purple-blue styling.

The direction is an original implementation influenced by the calm hierarchy,
disciplined spacing, typography-led grouping, restrained color, and focused
creative-workspace qualities users associate with products such as Claude and
Fable. JStack does not copy their proprietary themes, layouts, branding,
assets, or source code and implies no affiliation or endorsement.

## Git-Bound Evidence Lifecycle

For applicable Git work, obtain `jstack_ui_contract` on a clean baseline before
implementation. The receipt binds the exact project, policy, design profile,
platforms, themes, surfaces, states, viewports, existing-system evidence, and
catalog. Implement and review the change, commit it, then obtain the exact
build-command QA receipt required by the contract.

Write the evidence manifest and referenced artifacts only beneath the private,
server-selected `~/.jstack/evidence/ui/<project-key>/` root. The bounded v1
matrix requires `normal` for every surface/platform/theme/viewport and each
other applicable state at the designated primary viewport; every omitted v1
state needs a typed reason in `stateExclusions`. Objective results must cover
each surface/platform and bind the exact matrix cells they aggregate. Use the
published `ui-objective-result.v1` and `ui-product-observation.v1` JSON schemas,
then call `jstack_ui_finalize` with the current build and runtime digests. The
candidate must be clean and a strict descendant of the contracted baseline.
Any byte, Git, policy, catalog, QA, matrix, or evidence drift requires fresh
evidence.

Release readiness computes applicability from the actual base-to-candidate
diff. An applicable UI change requires the current UI finalization receipt in
addition to the existing QA, security, audit, launch, review, approval,
rollback, monitoring, and smoke evidence. A UI receipt never authorizes a
commit, push, merge, release, deployment, production action, or scope increase.

Artifact-only projects may use the skill and planning guidance, but cannot
receive the Git-bound contract or finalization receipts.

Windows supports automatic routing and session-local contract planning, but
Beta.2 UI finalization fails closed because the stdlib-only server cannot
verify evidence privacy against inherited DACLs and reparse points. A
release-bound UI lifecycle must begin and finish on a supported POSIX host;
root-bound receipts are not portable between machines.

## Adapter Maturity

| Adapter | Beta.2 status |
| --- | --- |
| Web | Qualified evidence contract |
| Webview, Electron, Tauri | Contract-only pending host or packaged-shell provenance evidence |
| iOS, Android, React Native, Flutter | Contract-only pending exact target-runtime evidence |
| macOS, Windows, Linux native | Contract-only pending exact target-runtime evidence |

Status is per adapter, not a claim that one preview proves another platform.
Platform-native navigation, semantics, input, accessibility, focus, and motion
remain required where applicable.

## Install Or Upgrade

Validate the exact Beta.2 checkout first:

```bash
python3 scripts/sync_artifacts.py --check
python3 scripts/check_contract_compatibility.py
python3 scripts/check_product_boundaries.py
python3 -m evals.runner.cli verify-lock
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
git diff --check
```

For direct Layout A, use the transactional installer. It installs exactly one
direct Product Interface skill:

```bash
python3 scripts/install.py
```

The default does not edit `CODEX_HOME/AGENTS.md`. To explicitly opt into the
bounded global Product UI instruction block, use:

```bash
python3 scripts/install.py --manage-agents
```

For dedicated Layout B, keep all five plugins enabled, keep the umbrella plugin
uninstalled, and use the `product-ui-design` skill supplied by `j-stack-dev`.
Do not add a direct skill copy. Back up the published Beta.1 MCP directory,
plugin sources and caches, Codex configuration, marketplace state,
`AGENTS.md`, and `~/.jstack` as one rollback unit before activation.

After installation, restart Codex or open a new task. Verify all five manifests
and MCP initialization report `0.10.0-beta.2`, `tools/list` exposes 54
canonical tools and 52 legacy aliases, the two UI tools have no `gstack_*`
counterparts, and exactly one active `product-ui-design` skill exists.

## Compatibility

- Existing Beta.1 non-UI canonical requests remain supported. The declared
  UI-aware successors add only the exact optional Product Interface receipt
  fields and terminal `ui` verifier values needed by affected loop, program,
  and release-readiness requests; removing those additions reconstructs every
  frozen prior schema digest.
- Non-UI persisted loop and program state remains readable. UI-bound work uses
  successor state that explicitly carries the UI contract/evidence binding;
  the new requirement is not hidden in prose or an unrelated receipt.
- Existing Beta.1 receipts are version- and state-bound and therefore must be
  reacquired for a Beta.2 candidate.
- Beta.1 Proof registrations, descriptors, image assets, tasks, and evidence
  keep their Beta.1 version and exact-tag binding. Do not rewrite them to
  Beta.2.

## Rollback

Restore the backed-up Beta.1 plugin sources and caches, shared MCP directory,
Codex configuration, marketplace state, and prior `AGENTS.md` bytes together.
Preserve `~/.jstack` and Product Interface evidence for auditability unless an
explicit data-retention decision says otherwise. Restart Codex, then verify
all five plugins and MCP initialization again report `0.10.0-beta.1` with 52
canonical and 52 legacy tools.

Rollback invalidates Beta.2 QA, security, UI, audit, loop, program, launch, and
release receipts. It does not change the unvalidated status of the Beta.1
Proof Study.

## Limitations

- PNG validation and hashes prove the reviewed bytes, dimensions, matrix, and
  declared objective checks. They do not independently prove how or where a
  screenshot was captured.
- Product Designer observations remain structured model-authored evidence, not
  a guarantee of aesthetic quality or user preference.
- Human aesthetic approval is optional and external to the v1 producer
  manifest. Its absence does not block objective UI finalization, and JStack
  never fabricates, infers, or accepts a producer self-assertion of it.
- Contract-only adapters are not release-tested runtime implementations.
- UI-bound program phases run in the exact contracted program root in Beta.2;
  linked-worktree UI phases are rejected and must be split into a separately
  contracted program.
- Product Interface contract receipts survive POSIX MCP restarts through a
  private `~/.jstack/keys/ui-contract-hmac-v1` key. The key is not used for QA,
  audit, launch, finalization, or release receipts. Windows contract receipts
  remain session-local in Beta.2 because the stdlib-only server does not claim
  DACL/reparse guarantees it cannot verify.
- The Product Interface System does not confer ownership of third-party visual
  language, grant vendor affiliation, replace user research, certify WCAG
  conformance, or authorize production deployment.
