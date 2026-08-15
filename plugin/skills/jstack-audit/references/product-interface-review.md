# Product Interface read-only review

Use this reference only when `jstack_detect_project` reports Product Interface work as `required` or `review-required`, or the declared audit scope otherwise contains a user-facing interface. It is a read-only projection of the JStack Product Interface catalog, not authority to create a contract, edit the candidate, run the interface, or finalize UI evidence.

## Catalog binding

- Schema: `jstack.ui.catalog.v1`
- Catalog version: `1.0.0`
- Canonical catalog SHA-256: `75f041b52c85f9f3ef31606ab331271148eefa7bc6ea060580a787b2b811c465`
- Profiles: `editorial-calm`, `creative-canvas`
- Precedence: `explicit-user-direction`, `established-project-system`, `domain-default`, `editorial-fallback`
- Qualified adapters: `web`
- Contract-only adapters: `webview`, `ios`, `android`, `react-native`, `flutter`, `electron`, `tauri`, `macos`, `windows`, `linux`

If the installed catalog identity differs from this binding, report a coverage gap and stop the Product Interface portion of the audit rather than silently applying stale criteria.

## Review criteria

1. Confirm explicit user direction wins, then established project tokens, components, layout, accessibility, and brand rules, then the domain profile, then Editorial Calm fallback. Flag an unsolicited redesign or an unaccounted existing-system hint.
2. Confirm every surface has the intended profile. Editorial Calm should preserve quiet hierarchy, legibility, restrained chroma, subtle depth, and purposeful motion. Creative Canvas should prioritize the workspace, tool hierarchy, selection clarity, dense calm controls, and spatial continuity. Hybrid products may use a calm shell around creative surfaces.
3. Check the catalog defaults after precedence resolution: 4px spacing, 4/8/12px restrained radii, 1px separators, zero negative letter spacing, 120/180/240ms motion, light and dark for greenfield work, and preservation of every existing supported theme.
4. Challenge hierarchy, coherence, responsive reflow, keyboard and focus behavior, semantics, contrast, text scaling, reduced motion, touch targets, loading/empty/error/disabled/selected/success/destructive states, clipping, overlap, overflow, and critical canvas alternatives.
5. Challenge generic composition: unnecessary card stacks or nested cards, excessive pills, decorative gradients or orbs, giant dashboard headings, indiscriminate glass effects, one-note purple-blue styling, placeholder glyphs, or improvised assets.
6. Apply the exact adapter status above. A qualified label still needs the catalog's required evidence for that exact platform. A contract-only adapter cannot be promoted by screenshots, a browser preview, or evidence from another platform.
7. If a UI contract or finalization receipt is supplied, treat it only as cited evidence. Verify that its catalog, Git candidate, platform, theme, surface, state, viewport, build, and objective evidence bindings match the audited subject. Never infer capture honesty, subjective aesthetic approval, QA, security, release readiness, or deployment authority from it.

Report every Product Interface finding through the normal audit finding contract with exact source or evidence citations. Separate objective failures from subjective observations, expose unsupported coverage, and do not call visual quality proven merely because the deterministic evidence shape passes.
