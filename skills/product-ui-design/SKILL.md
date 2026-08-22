---
name: product-ui-design
description: Design, implement, modify, or review user-facing graphical interfaces with JStack's Product Interface System. Use automatically for frontend and UI work involving screens, routes, components, forms, dashboards, mobile or native views, webviews, desktop windows, or canvas, editor, and timeline experiences, including visual, responsive, interaction, accessibility, and visual-QA changes. Do not use for backend-only, API-only, infrastructure, data, CLI or TUI, or documentation-only work with no graphical user-facing surface.
---

# Product UI Design

Create coherent, accessible product interfaces with an original design language influenced by the general craft qualities of Claude-like editorial clarity and Fable-like creative confidence. Never copy a vendor's proprietary branding, assets, source, themes, or layouts, and never present JStack output as an Anthropic or Fable design.

## Apply the system

1. Confirm that the scoped work changes or evaluates a graphical user-facing surface. For mixed repositories, inspect the requested surfaces and changed paths; do not impose UI gates on backend-only changes.
2. Inspect the product before making visual decisions. Find similar screens and flows, tokens, stylesheets, components, brand assets, accessibility patterns, and platform conventions.
3. Resolve design direction in this order:
   - explicit user direction and supplied visual sources;
   - the established project design system;
   - the domain-appropriate profile;
   - `editorial-calm` as the fallback.
4. Use preserve-and-extend for an existing product. Do not start a redesign, add an unsupported theme, or replace established components unless the user explicitly scopes that change.
5. Choose a profile per surface. Use `editorial-calm` for content, operations, finance, SaaS, assistants, settings, dashboards, CRM, and data-heavy products. Use `creative-canvas` for visual creation, media, animation, games, canvases, node editors, and timelines. Use a hybrid when an Editorial Calm shell contains a Creative Canvas workspace.
6. Before implementing interaction, inventory the meaningful controls, conditional states, overlays, navigation changes, loading behavior, and direct manipulation in scope. Classify frequency and input modes, state why motion helps or should be omitted, and select the smallest runtime technique supported by the existing project.
7. Implement the complete core experience with realistic bounded content and all applicable interaction states. Prefer semantic, platform-native controls and the project's proven components. Apply the shared motion specification instead of inventing per-component timings.
8. Verify the result at runtime before declaring it complete. Exercise rapid repeated input, interruption, cancellation, keyboard focus, and reduced motion. For a JStack motion specification, produce its bounded candidate measurements, call `jstack_ui_motion_finalize`, and bind the passing receipt into ordinary UI finalization. Treat automated evidence as objective coverage, not proof of producer honesty or subjective aesthetic quality.

## Load only the needed references

- Read [profiles.md](references/profiles.md) when selecting, combining, or reviewing profiles.
- Read [tokens.md](references/tokens.md) when creating or changing visual styles, layout, typography, color, elevation, or motion.
- Read [motion-intelligence.md](references/motion-intelligence.md) for every implementation or review involving controls, navigation, conditional rendering, overlays, expansion, loading, notifications, direct manipulation, or animation. Do not load it for static presentation-only work with no interaction change.
- Read [platform-adapters.md](references/platform-adapters.md) only for the target platforms and frameworks.
- Read [accessibility.md](references/accessibility.md) for every implementation or review that affects interaction, presentation, or content structure.
- Read [evidence-and-visual-qa.md](references/evidence-and-visual-qa.md) when implementing, reviewing, testing, or finalizing a UI change.

## Coordinate with adjacent workflows

- When a visual source must be explored, selected, cloned, or compared, make one handoff to the available Product Design workflow and follow its source-capture and visual-selection contract. This skill supplies product standards; it does not duplicate that workflow or route back into itself.
- Use the user's selected browser-control workflow for runtime interaction and screenshots. This skill defines the required coverage; browser tooling captures it. Do not switch browsers or invoke raw browser automation when the governing workflow requires user approval.
- For applicable JStack work, obtain `jstack_ui_contract` before implementation and follow its returned profile, surfaces, themes, viewports, platforms, and evidence matrix. When the work changes meaningful interaction, call `jstack_ui_motion_spec` on that same clean baseline with a complete bounded interaction inventory and one repository-grounded runtime strategy per contracted platform. Implement the returned specification. After the candidate is clean and verified, use the selected browser or native harness to write canonical motion-result artifacts and one motion-evidence manifest beneath the server-selected private UI evidence root; call `jstack_ui_motion_finalize`, then pass both its motion receipt and the original motion-spec receipt to `jstack_ui_finalize` with the ordinary UI evidence. Static presentation-only work omits both motion inputs. If those tools are unavailable, apply this skill locally and state that no JStack receipt was issued; never fabricate one.
- Retain the opaque UI contract receipt unchanged until finalization. It is not a deployment authorization or a substitute for fresh QA; do not paste its signing-key material or any private evidence into the repository.
- Retain the opaque motion-spec and motion-finalization receipts unchanged until UI finalization. The specification alone is guidance, while the finalization receipt attests only that the named bounded evidence passed deterministic checks for the exact candidate. Neither receipt authorizes project edits, dependencies, Git actions, release, deployment, external actions, or production changes.

## Guardrails

- Support light and dark themes for greenfield work. In existing products, preserve the themes already in scope unless the user requests another.
- Avoid generic AI styling: card grids without hierarchy, nested cards, excessive pills, decorative gradients or orbs, giant headings over sparse dashboards, indiscriminate glass effects, and default purple-blue palettes.
- Do not fake visible assets with emoji, ASCII, placeholder boxes, CSS art, improvised vectors, or hand-drawn SVGs. Reuse real project assets, a suitable icon library, or an approved asset-generation workflow.
- Keep controls stable as labels, validation, loading indicators, or counts change. Make primary navigation, controls, forms, and critical flows functional.
- Give meaningful input immediate feedback, then use restrained continuity only where it explains causality, direction, hierarchy, or object identity. High-frequency and keyboard-driven work stays instant or nearly instant. Reject universal hover-scale, pulse loops, stagger spam, uniform fade-on-mount, utility bounce, decorative parallax, and motion without a usability purpose.
- Honor reduced-motion preferences with explicit final-state substitutions. Preserve visible focus, semantic state, announcements, gesture alternatives, interruption safety, and stable layout; do not communicate state through movement alone.
- Do not claim accessibility from a linter alone or visual fidelity from screenshots alone. Record what was actually exercised and any remaining limitations.

## Report the result

State the selected profile and precedence rationale, the existing system preserved, scoped surfaces and platforms, motion inventory and omissions, runtime strategy, ordinary and reduced-motion behavior, themes and states verified, tests and visual evidence completed, and any unresolved blockers. Include JStack contract, motion-spec, motion-finalization, or UI-finalization receipt identifiers only when the tools actually issued them. When motion applies, distinguish a missing motion audit, a blocked audit, and a passing exact-candidate receipt; never imply that a receipt proves aesthetic quality, producer honesty, release readiness, or deployment authority.
