# ADR 0023: Global Product Interface System

- Status: Accepted
- Date: 2026-08-15
- Target release: 0.10.0-beta.2
- Supersedes: no prior design-system ADR
- Preserves: ADR 0021 and ADR 0022 Beta.1 Proof boundaries

## Context

JStack already governs intent, delivery, evidence, durable iteration, and
release safety, but it did not give user-facing interface work a consistent
product-design standard or an objective visual-evidence lifecycle. General
models can produce capable backend code while still drifting toward generic UI
patterns, disregarding an established product language, or declaring a visual
change complete from prose alone.

The product owner requested stronger influence from the qualities associated
with Claude and Fable interfaces. The useful qualities are abstract design
principles—calm hierarchy, disciplined spacing, restrained color,
typography-led grouping, clear focus, and canvas-centered creative work—not a
license to reproduce any vendor's protected implementation or identity.

The system must activate naturally across JStack without adding another command
or altering staffing authority. It must work across web, webview, mobile,
cross-platform, and desktop targets, but must not describe untested adapters as
runtime-qualified. It must add evidence without weakening existing QA,
security, audit, launch, release, human-authority, or Beta.1 Proof boundaries.

## Decision

### 1. One automatic skill, no sixth command

JStack ships `product-ui-design` as an automatically triggered skill for
user-facing interface scope inside the five existing workflows. Backend-only
and non-interface work is inactive. Repository hints without a user goal or
changed UI path are review-required rather than an unsolicited redesign.

The skill is capability guidance only. It adds no role, write scope,
permission, tool authority, external action, release authority, or production
access.

### 2. Preserve-and-extend precedence

Design resolution is deterministic:

1. explicit user instruction;
2. the existing project design system;
3. the domain profile;
4. the `editorial-calm` fallback.

Existing tokens, components, layouts, accessibility requirements, and brand
rules are evidence, not obstacles. JStack preserves and extends them unless the
user explicitly requests redesign. Greenfield interfaces implement light and
dark themes; existing interfaces retain their supported theme contract.

### 3. Two profiles and hybrid composition

`editorial-calm` covers content-heavy, settings, account, research,
administrative, and workflow surfaces. `creative-canvas` covers visual
creation, timelines, nodes, spatial editing, media, and similar workspaces.
Hybrid products use editorial calm for the shell and creative canvas for the
workspace.

Both profiles share a 4px spacing base, 4/8/12px radii, 1px separators, zero
negative letter spacing, restrained elevation, 120/180/240ms purposeful
motion, reduced-motion behavior, accessible semantic state, and platform-native
interaction. They avoid unstructured card walls, nested cards, excessive
pills, decorative gradient/orb backdrops, oversized headings, glassmorphism,
and generic purple-blue sameness.

### 4. Original influence, not reproduction

JStack may use high-level influence from polished editorial and creative tools,
including qualities associated with Claude and Fable. It must produce original
tokens, components, compositions, and code for the actual project. It must not
copy proprietary themes, layouts, assets, branding, trade dress, or source
code, and it must not imply affiliation, endorsement, or vendor parity.

### 5. Separate catalog and canonical-only tools

The Product Interface catalog is JStack-native and separate from the external
specialist capability catalog. Beta.2 adds `jstack_ui_contract` and
`jstack_ui_finalize`, taking the live surface to 54 canonical `jstack_*` tools.
The legacy surface is frozen at 52 `gstack_*` aliases. No UI aliases are added.
The commands and role model remain unchanged.

### 6. Explicit Git-bound lifecycle

`jstack_ui_contract` records a clean exact-Git baseline, project/policy/catalog
identity, applicability, profiles, themes, platforms, surfaces, states,
viewports, and hashed existing-system evidence before implementation.
Its self-contained receipt uses a dedicated private per-user POSIX signing key
beneath `~/.jstack/keys`, separate from session-local QA, audit, launch, and
finalization receipts. Freshness is still required when starting new durable
work; an expired contract may only finish its exact descendant through the
full current-state finalizer. On platforms where stdlib-only code cannot
verify the persistent key's ACL and reparse ancestry, the contract remains
session-local rather than persisting a weaker secret.

`jstack_ui_finalize` requires a clean strict-descendant candidate, the exact
discovered-build QA receipt, build/runtime digests, a complete contract-derived
capture matrix, objective adapter checks, and structured Product Designer
observations. Evidence lives only beneath a fixed server-selected private root
under `~/.jstack/evidence/ui/`; caller-selected repository roots are rejected.
Strict bounded manifests, descriptor-safe reads, regular/private files,
content hashes, validated PNG structure/dimensions, critical-surface coverage,
and drift rechecks fail closed. Beta.2 cannot establish equivalent private-file
ACL and reparse guarantees through its stdlib-only Windows runtime, so Windows
supports routing and session-local contract planning but UI finalization fails
closed. The complete root-bound lifecycle must begin and finish on a supported
POSIX host. On POSIX, the v1 privacy boundary verifies current UID, regular-file
shape, link count, and restrictive mode bits; it does not inspect macOS/NFSv4
extended ACL grants, so ACL-shared evidence or key roots are unsupported.

UI applicability and receipts propagate explicitly through plan, team, loop,
program, and release-readiness contracts. Persisted v1 state remains readable;
UI-bound successors carry their new requirement openly. Release readiness
evaluates the actual base-to-candidate diff, not repository hints alone.

Beta.2 UI contracts bind one exact repository root as well as its clean
baseline fingerprint. A UI-bound program phase therefore runs in the program
root; it may not request a linked worktree. Work requiring an isolated UI
worktree must be split into a separately contracted program. This explicit
fail-closed limitation avoids weakening the root and fingerprint binding.

The finalization receipt is evidence only and always non-authorizing. It never
replaces QA, security, review, audit, launch, release-owner approval, rollback,
monitoring, smoke evidence, host/provider controls, or explicit deployment
scope. Artifact-only work may use design guidance but cannot receive Git-bound
UI receipts.

### 7. Objective evidence and optional human aesthetics

The bounded v1 matrix captures `normal` for every contracted
surface/platform/theme/viewport and each other applicable state at the single
designated primary viewport. Every omitted v1 state requires a typed exclusion
and reason. Adapter-appropriate critical-flow, keyboard/focus, accessibility,
reduced-motion, and text-fit/overflow results cover every surface/platform and
bind the exact matrix cells they aggregate. Product Designer observations must
cover critical surfaces and cannot silently dismiss blockers.

Human aesthetic approval remains optional and external to the v1 producer
manifest. The manifest cannot authenticate or self-assert a human reviewer;
only a future independently authenticated channel may carry that label. Its
absence does not block objective finalization, and no model, fixture, or
self-attestation may be described as human review. Screenshot validation proves bytes, dimensions,
coverage, and declared checks; it does not independently prove capture honesty,
runtime provenance, visual excellence, usability, or user preference.

### 8. Adapter maturity is visible

Web has a qualified evidence contract in Beta.2. Webview, Electron, Tauri, iOS,
Android, React Native, Flutter, macOS, Windows, and Linux are contract-only until
their exact host, packaged, or target runtimes provide independently bound
provenance and the required evidence.
Evidence from one adapter never qualifies a different adapter.

### 9. Distribution has one active copy

Direct Layout A installs one direct `product-ui-design` skill. Global managed
`AGENTS.md` activation is a separate explicit `--manage-agents` opt-in; the
default preserves that file. Managed writes use bounded markers, reject
unsafe/malformed targets and preimage drift, preserve unrelated bytes and
newline style plus POSIX owner/group/mode (or the Windows security descriptor),
and participate in transactional rollback. Extended ACLs, xattrs, and file
flags are not claimed as portable metadata guarantees. Exact displaced objects
are retained in one bounded private latest-success recovery set; another
upgrade fails before mutation until the operator verifies and explicitly
archives or removes it. Failed or conflicted transactions keep separate
recovery objects rather than deleting a possible open-descriptor edit.

Dedicated Layout B gets its single skill copy from `j-stack-dev`; the umbrella
plugin is an alternative. Installation fails before mutation when an enabled
plugin would create a duplicate direct copy. Restart or a new Codex task is
required for discovery after activation.

### 10. Beta.1 Proof remains frozen and unvalidated

No Product Interface file, tool, schema, or Beta.2 server byte is imported into
the Beta.1 Proof Plane. CI uses full Git history to export and probe the exact
annotated `v0.10.0-beta.1` 52-tool server. The Beta.1 image qualifications,
216 attempts, 432 independent reviews, scoring, and evidence verification
remain pending, and Beta.2 enables no study, uplift, superiority, stable, or
production-readiness claim.

## Consequences

- UI work receives consistent design intent automatically while explicit user
  and project context continue to win.
- A separate catalog can evolve without conflating UI policy with specialist
  staffing capabilities.
- Visual completion becomes tied to objective, exact-state evidence, while the
  remaining subjective and provenance limitations stay visible.
- Native targets can adopt the contract now without being mislabeled as
  qualified implementations.
- Existing workflows, roles, legacy aliases, and non-UI persisted state remain
  compatible.
- Global activation is intentional and recoverable, and duplicate skill copies
  fail closed.

## Rejected Alternatives

- A `/jstack-ui` sixth command: rejected because interface quality is a
  cross-cutting concern within the existing delivery modes.
- Always forcing a new JStack visual language: rejected because it would erase
  product identity and turn maintenance work into unsolicited redesign.
- Copying a Claude or Fable theme, layout, assets, branding, or source:
  rejected because inspiration does not require proprietary reproduction or
  misleading affiliation.
- Treating all platform adapters as qualified: rejected because contract
  availability is not target-runtime evidence.
- Making human aesthetic review mandatory: rejected because it would block the
  approved objective Beta.2 lifecycle when reviewers are unavailable; when
  provided, human evidence remains distinct and explicit.
- Letting screenshots or a UI receipt replace existing release gates: rejected
  because visual evidence does not prove correctness, security, operational
  readiness, deployment authority, or production safety.
- Updating the Beta.1 Proof assets to probe Beta.2: rejected because it would
  destroy the frozen study boundary and require a new preregistered study.
