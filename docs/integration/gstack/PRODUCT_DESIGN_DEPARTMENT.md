# Stage 10 — Product / Design Department

## Status and authority

| Item | Value |
| --- | --- |
| Program stage | Stage 10 — Product / Design Department |
| Authoritative requirements | `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md`, sections 9.7 and 27 plus Stage 10 |
| Execution wrapper | Attached Final Codex Master Prompt, Product / Design Intelligence and Stage 10 sections |
| JStack baseline | `49cf545d940c43b394ea35ed78b5ab5742d7bcf7`, tree `0afa6b60047de246fc699ce098d6a8a587cac227` |
| gstack baseline | `ad8400543cd9ce8d07641362db48d44a95417e33`, tree `993294b0a09f5265d2d5af6d2fb8234ae2efe450`, version `1.69.0.0` |
| Advance gate | **PASS** — design exploration cannot mutate the candidate or production without separate implementation authority |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

The attached MD remains the source of truth. The master prompt remains its
execution wrapper. This stage adds only the Product/Design integration they
require. It does not implement the later Browser Provider, Browser QA
remediation handoff, delivery pipeline, profile, release, hardening,
modularity, cross-host, or proof stages.

## Upstream review and disposition

The implementation reviewed the pinned MIT-licensed source files:

- `design-consultation/SKILL.md.tmpl`;
- `design-review/SKILL.md.tmpl`;
- `design-shotgun/SKILL.md.tmpl`;
- `design-html/SKILL.md.tmpl`;
- `plan-design-review/SKILL.md.tmpl`.

Useful general methods were re-expressed as original JStack contracts and host
instructions: product context, coherent design rationale, hierarchy and
AI-slop analysis, bounded distinct alternatives, explicit selection,
design-system reuse, state coverage, accessibility, implementation guidance,
and runtime verification handoff.

The stage does **not** copy an upstream prompt, persona, wording, command,
router, state store, taste memory, updater, provider, browser runtime, model
selection, multi-agent fan-out, dependency installer, auto-commit, or source
mutation behavior. `design-shotgun` remains a provider candidate only for the
visual generation portion; no provider is activated before Stage 11.
`design-review` browser execution and automatic fixes remain deferred to the
later provider and QA/remediation stages.

## Architecture decision

Stage 10 extends the existing Product Interface capability family:

```text
approved compiled request
  → existing Product/Design specialists and Stage 8 methods
  → repository-grounded analysis
  → one directed path or two/three bounded alternatives
  → explicit human selection
  → normalized Product/Design decision
  → existing jstack_ui_contract receipt
  → separately authorized Builder implementation
  → existing motion, browser/runtime QA, UI evidence, and finalization
```

There is no new command, MCP tool, router, provider, persistence system,
canonical role, physical-agent rule, or design authority. Existing Product
Strategist, Design Lead, Product Designer, Design Systems Engineer,
Accessibility Specialist, Frontend Engineer, and Browser QA specialist records
remain logical capability coverage selected by the Team Composer. They do not
automatically become separate physical agents.

The Stage 8 Product Discovery, CEO and Product Review, Design Plan Review, and
Developer Experience Review methods remain the analysis methods. Stage 10 does
not duplicate their intake, questions, receipts, or routing. The Adaptive
Context Gate still owns at most three material questions per round.

## Design precedence

The machine policy and Product UI skill use the specification's exact order:

1. explicit user requirements;
2. existing application design system;
3. existing tokens and components;
4. existing accessibility requirements;
5. approved evidence/reference bundle;
6. selected product/domain guidance;
7. fallback JStack design guidance.

Each material finding and alternative names digest-only source references.
Every alternative must trace to explicit user requirements. A selected
direction for an established system must trace to verified repository
evidence. A selected direction with a bound reference bundle must trace to
that signed bundle. Lower-ranked guidance cannot silently override a
higher-ranked source.

## Proportional decision paths

`jstack.ui.design-decision-input.v1` supports three paths:

- `preserve-and-extend`: exactly one repository-grounded direction;
- `directed`: exactly one direction already selected by explicit user
  instruction or an approved compiled prompt;
- `exploration`: exactly two or three materially distinct alternatives plus
  the `design-alternatives` capability.

Each alternative covers product rationale, hierarchy, user flow,
design-system strategy, visual direction, interaction, responsive behavior,
accessibility, applicable states, trade-offs, implementation guidance, and
source references. The bound normalized form is
`jstack.ui.design-decision.v1`.

Human selection is mandatory. Active-conversation approval is converted to a
SHA-256 digest; raw approval text is not retained. When selection comes from
the Evidence Builder, the selected prototype must match the signed reference
bundle. Silence is never a selection. Replacing an established system still
requires the separate existing `redesign_approved` boundary and accountable
redesign approval digest.

## Product Interface contract successors

The decision is an optional field on the existing `jstack_ui_contract` tool:

| Contract | Binding |
| --- | --- |
| `jstack.ui.contract.v1` | Existing ordinary UI contract |
| `jstack.ui.contract.v2` | Existing UI contract plus reference bundle |
| `jstack.ui.contract.v3` | UI contract plus Product/Design decision |
| `jstack.ui.contract.v4` | UI contract plus both bindings |

The original v1 and v2 field sets and callers remain unchanged. New v3 and v4
schemas are closed additive successors. The contract digest binds the selected
direction, its sources, policy version, baseline, profile resolution,
reference bundle when present, surfaces, allowed paths, states, platforms,
themes, viewports, and evidence matrix. Existing motion specifications accept
all four contract versions.

The normalized decision carries immutable false values for implementation,
candidate mutation, production mutation, and provider invocation, plus
`authorityEffect=none`. `jstack_ui_contract` still returns
`executionAuthorized=false`. A UI receipt remains readiness evidence rather
than action authority.

## Exploration flow and host boundary

The host-facing Product UI skill follows the normative flow:

```text
request
→ Product / Design team
→ bounded alternatives
→ human selection or requested revision
→ selected reference
→ separately authorized JStack implementation
→ browser/runtime QA
→ UI evidence
→ finalization
```

The deterministic MCP can validate alternative count, source traceability,
approval digest, reference selection, existing-system disposition, schema,
baseline, receipt, and zero-authority invariants. It cannot prove a human's
identity or intercept arbitrary host-native edits. Host skill compliance must
display alternatives and wait for the user's selection. Ordinary JStack task
mode, readiness, Team Plan, host permissions, and action boundaries still
control implementation and external effects.

Text alternatives can remain conversational. Visual alternatives use the
existing Evidence Builder, which caps isolated prototypes at two and performs
no candidate mutation. No automatic provider invocation or multi-agent fan-out
was added.

## Privacy and security

- Raw approval text, raw reference content, source contents, secrets, and
  hidden reasoning are excluded from the normalized decision and receipt.
- Source material is data, identified by bounded IDs, classifications, and
  SHA-256 digests.
- All objects use exact field sets, bounded arrays, bounded text, portable IDs,
  and deterministic canonical digests.
- Unknown fields, unselected alternatives, false reference claims, reference
  prototype mismatches, unapproved system replacement, weakened authority, and
  stale policy bindings fail closed.
- The implementation is standard-library only and adds no network, provider,
  Node, Bun, model, browser, filesystem-write, Git, or deployment dependency.

## Compatibility and rollback

The public surface remains six commands, 59 canonical tools, and 52 frozen
aliases. There is no `gstack_ui_*` alias or new command. Canonical files flow
through `scripts/sync_artifacts.py` into the umbrella plugin and dedicated
Product UI skill mirror. The immutable upstream provenance record binds the
pinned sources to the original local implementation.

Rollback removes the optional `design_decision` input, v3/v4 and decision
schemas, the pure validator, Stage 10 documentation, and host guidance. Existing
v1/v2 Product Interface, reference, motion, evidence, and finalization paths
remain usable throughout.

## Advance-gate verification

Stage 10 may be marked PASS only after tests prove:

1. existing v1/v2 contracts remain byte-shape compatible;
2. v3/v4 and the normalized decision validate against closed schemas;
3. alternatives are capped and a valid human selection is mandatory;
4. raw approval text does not survive normalization;
5. reference and established-system precedence fail closed;
6. the tool leaves the repository unchanged;
7. decision, contract, and response all deny implementation and production
   authority;
8. host instructions require display and human selection before implementation;
9. tool, command, alias, dependency, sync, and immutable-provenance boundaries
   remain green.

## Measured result

The Stage 10 candidate passed:

- 161 focused Product Interface, reference, motion, methodology,
  investigation, organization, Team Composer, dynamic-mode, schema,
  compatibility, sync, and provenance tests with 11 declared optional or
  platform skips;
- the full repository suite: 1,080 tests, 13 declared optional or platform
  skips, zero failures, in 776.671 seconds;
- alpha.9 contract compatibility;
- six-command, 59-canonical-tool, 52-frozen-alias, and standard-library-core
  product boundaries;
- canonical/generated sync and pinned 761-file, 10-record gstack provenance;
- canonical and packaged MCP JSONL smoke tests;
- Python compilation and `git diff --check`.

The two optional JSON Schema validation tests remained skipped because the
optional `jsonschema` package is not installed; the production-standard-library
deterministic validators, schema structure/closure tests, runtime/schema enum
parity tests, and representative v1–v4 contract tests passed. No dependency was
installed to change that environment.

**Advance-gate decision:** Stage 10 is complete at the local candidate. This
PASS does not authorize Stage 11 or any commit, release, deployment, global
installation, provider invocation, candidate mutation, or production action.
