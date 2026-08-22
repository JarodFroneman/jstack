# Foundation tokens

Use the project's established tokens first. Introduce these foundations only for missing roles or greenfield work, and encode them as semantic variables rather than scattering literal values.

## Spacing and geometry

- Base all spacing on 4px increments. A practical scale is `0, 4, 8, 12, 16, 20, 24, 32, 40, 48, 64`.
- Keep standard radii between 4px and 12px: 4px for compact controls, 8px for ordinary controls and small surfaces, and 12px for prominent surfaces.
- Reserve fully rounded geometry for controls whose meaning requires it, such as a switch track, status dot, avatar, or compact tag. Do not make every button or container a pill.
- Use 1px separators for most boundaries. Add elevation only when it communicates stacking, attachment, drag state, menus, dialogs, or transient overlays.
- Avoid nested containers when spacing, alignment, a heading, or one separator establishes the same hierarchy.

## Typography

- Use the product's licensed typefaces and platform fallbacks. Choose roles for display, heading, body, label, code, and comparative numeric text.
- Use zero or positive letter spacing; do not apply negative tracking. Keep line height readable and avoid oversized headings that consume useful workspace.
- Use tabular numerals for changing or compared values such as finance, telemetry, timelines, and property panels.
- Preserve text layout under long labels, localization, validation messages, text scaling, and dynamic data.

## Color and themes

- Define semantic roles such as canvas, surface, raised surface, text, muted text, separator, accent, focus, success, warning, error, and destructive action.
- Derive light and dark roles independently; do not create dark mode by mechanically inverting colors. Avoid pure black for large dark surfaces when a softer neutral preserves hierarchy.
- Meet accessible contrast and never use hue as the only indication of status, selection, error, or focus.
- Use one purposeful accent family by default. Let the product's content or objects provide additional color instead of filling the chrome with decorative gradients.

## Motion

- Preserve an established project motion scale. For missing roles or greenfield work, use `instant` 0ms, `press` 80ms, `fast` 120ms, `standard` 180ms, `spatial` 240ms, and `deliberate` 320ms. Treat 320ms as a ceiling for rare meaningful transitions, not a universal page duration.
- Use separate standard, entrance, exit, and linear-progress easing roles. Exits are normally faster or quieter than entrances. Use the `settle` and `spatial` spring characters only where the runtime supports interruption safely; never apply one spring to every component.
- Use semantic distance tiers of 0, 2, 4, 8, and 16px; scale roles of identity, 0.98 press, and 0.985 subtle entrance; no blur by default with 4px measured subtle and 8px maximum; and no stagger by default with 20ms tight and 40ms maximum.
- Match the motion budget to interaction frequency. Rare interactions may use purposeful spatial continuity, routine interactions stay restrained, frequent interactions use press or fast feedback without travel or stagger, and continuous or keyboard-driven interactions remain direct or instant.
- Prefer opacity and transforms. Measure clipping, shadows, filters, masks, and large composited layers. Avoid layout animation that shifts an active target, causes cumulative layout shift, or queues stale transitions after rapid input.
- Preserve a visible and semantic final state when reduced motion is enabled. Remove travel, scale, blur, parallax, zoom, inertial effects, and nonessential repetition instead of merely slowing them down. Keep focus, announcements, progress, and state meaning intact.
- Read [motion-intelligence.md](motion-intelligence.md) for the interaction matrix, runtime selection, omission rules, and motion QA contract.

## Component behavior

- Keep a control's external dimensions stable across idle, hover or pressed, focused, loading, disabled, selected, success, and error states.
- Reserve space for icons, spinners, counts, helper text, and validation where their appearance would otherwise shift nearby content.
- Use shared primitives for focus rings, separators, labels, inputs, menus, dialogs, notifications, and semantic status treatment.
- Check compact, normal, long-text, empty, error, and dense-data cases before extracting a component as reusable.
