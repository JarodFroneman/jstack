# Design profiles

Use profiles as adaptable craft direction, not branded themes. Explicit user direction and an established project system always take precedence over these defaults.

## Resolve profiles

| Context | Default | Design intent |
| --- | --- | --- |
| Content, finance, operations, SaaS, assistants, settings, CRM, data-heavy products | `editorial-calm` | Make hierarchy, reading, comparison, and deliberate action feel effortless. |
| Visual creation, animation, media, games, canvases, node editors, timelines | `creative-canvas` | Prioritize the work surface, tool confidence, selection clarity, and spatial continuity. |
| Product shell around a creation surface | Hybrid | Map the shell to `editorial-calm` and the workspace to `creative-canvas`; share foundations and semantics. |

Resolve profiles per surface, not merely per repository. Record a default profile plus explicit surface mappings for a hybrid. Do not silently restyle adjacent surfaces.

## Editorial Calm

- Use a quiet information hierarchy, restrained chroma, generous but purposeful negative space, and a readable content measure.
- Let typography, alignment, separators, and grouping carry structure before adding containers or elevation.
- Use one purposeful product accent plus semantic status colors. Keep light and dark themes calm and distinct without reducing contrast.
- Prefer stable page frames, clear primary actions, compact secondary actions, and direct language.
- Use motion to clarify state change or continuity, never to decorate a static screen.
- Keep routine controls and data work on press or fast timing. Reserve spatial timing for occasional navigation, disclosure, or object continuity that materially improves orientation.

## Creative Canvas

- Give the canvas, stage, timeline, or editor the largest coherent region; keep surrounding chrome calm and compact.
- Separate global navigation, creation tools, object properties, and contextual actions by function and placement.
- Make selection, focus, active tool, object hierarchy, zoom, and destructive actions unambiguous without relying on color alone.
- Preserve spatial context during panels, modes, zoom, playback, and object changes. Avoid movement that shifts a user's target unexpectedly.
- Couple direct manipulation to input, then use a restrained interruptible settle after release. Dense tools, keyboard shortcuts, scrubbing, and repeated property changes must not replay entrance motion.
- Keep dense controls legible through rhythm, alignment, progressive disclosure, and keyboard access rather than shrinking everything.

## Hybrid composition

- Share type roles, spacing scale, semantic colors, focus treatment, and motion durations across the shell and workspace.
- Permit different density and surface treatment where the task changes: comfortable reading in the shell, compact tools around the canvas.
- Make the transition explicit through layout and hierarchy, not a competing palette or unrelated component library.
- Test cross-surface flows such as opening a project, editing it, saving, exporting, error recovery, and returning to the library.
- Share semantic motion tokens while allowing the shell and workspace to spend them differently: calm route and overlay continuity in the shell, direct manipulation and object continuity in the workspace, and near-instant repeated tools in both.

## Existing products and themes

- Identify which tokens and components are authoritative and cite their paths in the work report.
- Preserve every theme in the requested scope. Add both light and dark modes for a greenfield product; do not force a second theme into an existing product without scope.
- If a supplied visual source conflicts with an existing system, follow the user's explicit direction and state the tradeoff instead of blending them arbitrarily.
- Reject requests to reproduce a proprietary vendor product pixel for pixel. Translate high-level qualities into an original product-specific solution.
