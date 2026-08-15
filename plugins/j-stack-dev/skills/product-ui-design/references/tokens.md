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

- Use the shared duration tokens: 120ms for immediate feedback, 180ms for ordinary state transitions, and 240ms for meaningful spatial transitions.
- Use restrained easing with a fast response and gentle settle. Animate opacity and transforms when practical; avoid layout animation that moves interaction targets.
- Preserve a visible final state when reduced motion is enabled. Remove parallax, zoom, long travel, and nonessential repeated motion; do not merely slow them down.

## Component behavior

- Keep a control's external dimensions stable across idle, hover or pressed, focused, loading, disabled, selected, success, and error states.
- Reserve space for icons, spinners, counts, helper text, and validation where their appearance would otherwise shift nearby content.
- Use shared primitives for focus rings, separators, labels, inputs, menus, dialogs, notifications, and semantic status treatment.
- Check compact, normal, long-text, empty, error, and dense-data cases before extracting a component as reusable.
