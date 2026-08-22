# Product UI motion intelligence

Use motion to explain interaction and state, not to prove that the interface is
animated. Every meaningful interaction needs immediate, legible feedback, but
that feedback may be an instant state change. Frequent and keyboard-driven work
usually benefits from less motion than occasional spatial navigation.

## Build the motion brief before implementation

1. Inspect the existing runtime, dependencies, tokens, CSS, components, route
   transitions, overlays, conditional rendering, loading behavior, and
   platform conventions. Cite the paths that establish the current approach.
2. Classify the product and each surface. Editorial, transactional, and
   data-dense work normally uses restrained state motion. Creation, media,
   canvas, and spatial work may use stronger continuity around objects and
   panels while keeping tools fast.
3. Inventory meaningful interactions. Map each item to a contracted surface,
   category, trigger, purpose, input modes, and frequency. Include an explicit
   omission reason when instant feedback is better than animation.
4. Select a runtime per contracted platform. Preserve an established runtime;
   otherwise prefer platform-native facilities, CSS, or the browser View
   Transitions API when its support and interruption behavior fit the product.
   Do not add an animation package without an explicit, evidence-backed
   dependency decision.
5. For Git-bound JStack work, call `jstack_ui_motion_spec` with the current
   `jstack_ui_contract` receipt before source edits. Implement its tokenized
   specification rather than inventing unrelated timings per component.
6. Verify ordinary and reduced-motion behavior with rapid repeated input,
   interruption, cancellation, keyboard operation, focus restoration, and
   realistic content. For JStack-bound work, encode the measurements in the
   published motion-result and motion-evidence contracts beneath the private UI
   evidence root, then call `jstack_ui_motion_finalize` before ordinary UI
   finalization.

## Frequency and input gate

| Frequency | Character | Default motion budget |
| --- | --- | --- |
| Rare | Purposeful and spatial when orientation improves | Up to the deliberate tier; no decorative sequence |
| Routine | Restrained state or spatial continuity | Fast through spatial tiers |
| Frequent | Immediate, subtle feedback | Press or fast tier; no nonessential travel or stagger |
| Continuous | Direct manipulation or instant state | Follow input directly; settle only after release when needed |

Keyboard shortcuts, command palettes, repeated table navigation, scrubbing, and
continuous adjustment must not replay entrance animation. Keep focus visible
and make selected, expanded, busy, invalid, or completed state clear without
requiring movement.

## Interaction specification

| Category | Purpose and typical treatment | Exit and reduced-motion treatment |
| --- | --- | --- |
| Button, link, navigation control | Acknowledge press or selection immediately. Keep the target's external dimensions stable; pointer press scale is optional and must not become universal hover-scale. | Release or dismissal uses press/fast timing. Reduced motion changes the state instantly. |
| Route or screen | Preserve direction only when it helps the user understand where content came from. Keep stable shell regions anchored. | Exit is shorter and quieter. Reduced motion uses an instant replacement or short opacity change. |
| Tabs and segmented controls | Connect the selected control to its panel without replaying the entire page. | The old panel leaves promptly; reduced motion updates selection and content directly. |
| Modal, dialog, drawer, or sheet | Establish stacking and origin while moving focus into the new surface. Use an anchored transform plus opacity where appropriate. | Dismiss toward the origin without delaying restored focus. Reduced motion keeps the overlay and focus change but removes travel and scale. |
| Popover, menu, or tooltip | Reveal from the invoking control with fast, origin-aware feedback. | Close faster than open. Reduced motion appears or disappears immediately or with brief opacity only. |
| Accordion or expandable content | Explain disclosure while protecting reading position and nearby targets. Reserve geometry before animating when possible. | Collapse promptly. Reduced motion switches directly to the final expanded state. |
| Card, list, insert, delete, sort, filter, or reorder | Preserve item identity. Use transform and opacity for stable list geometry; direct drag follows input. | Removed items leave before remaining items settle. Reduced motion uses explicit state and stable ordering. |
| Form validation and submission | Attach feedback to the affected field or action without shaking the page. Keep labels, spinners, and success icons dimensionally stable. | Clear obsolete feedback quickly. Reduced motion preserves text, icon, live-region, focus, and busy state. |
| Loading, skeleton, progress, or content replacement | Prevent an unresponsive pause and avoid abrupt flashes or layout shift. Prefer bounded progress; repeated indeterminate motion needs a real purpose. | Resolve promptly into stable content. Reduced motion uses static progress or a short opacity replacement. |
| Toast or notification | Show source and priority without blocking current work. Pause or expose controls when timing affects comprehension. | Dismiss quietly. Reduced motion retains announcement, duration, and controls without travel. |
| Icon transition or shared element | Preserve compact control or object identity when the relationship is real and runtime support is reliable. | Fall back to an ordinary state change if interrupted. Reduced motion swaps state or uses opacity only. |
| Gesture | Track the pointer or touch position directly; use a restrained settle only after release. Always provide a non-gesture alternative. | Cancellation returns predictably. Reduced motion keeps direct manipulation and removes inertial or decorative travel. |

## Token contract

Use semantic tokens and map them through the project's existing token system:

- Duration: `instant` 0ms, `press` 80ms, `fast` 120ms, `standard` 180ms,
  `spatial` 240ms, and `deliberate` 320ms. The deliberate tier is a ceiling for
  rare meaningful transitions, not a page default.
- Easing: use a fast-response standard curve for state, a gentle decelerating
  entrance, a faster accelerating exit, and linear timing only for progress or
  input-coupled movement.
- Springs: `settle` is a subtle utility settle; `spatial` is a restrained
  object transition. Use a spring only when the chosen runtime can interrupt
  it safely; never apply one spring to every component.
- Distance: 0, 2, 4, 8, and 16px tiers. Large screen travel, parallax, and
  off-axis drift require a product-specific reason.
- Scale: identity, 0.98 press, and 0.985 subtle entrance. Scale must not shift
  layout, replace focus, or become a generic card-hover effect.
- Opacity: hidden, softened, and visible semantic states. Content must not
  remain inaccessible while visually transparent.
- Blur: no blur by default; 4px is a measured subtle option and 8px is the
  ceiling. Treat filters as a performance cost, not a free compositor effect.
- Stagger: none by default, 20ms tight, and 40ms maximum. Do not stagger
  routine page content, tables, search results, or repeated updates.
- Overlay depth: use the established semantic layer scale. A transient surface
  stays above its origin and below blocking dialogs; motion never substitutes
  for correct focus trapping and dismissal semantics.

## Runtime selection

- Preserve an existing, maintained project abstraction when repository
  evidence proves it is authoritative.
- For web state changes, start with CSS transitions and animations on opacity
  and transforms. Use clipping only when its performance is measured and it
  avoids unsafe layout animation.
- Consider View Transitions for genuine route or shared-element continuity only
  after checking browser support, interruption, focus, history, and
  reduced-motion behavior. It is not a universal navigation wrapper.
- Use platform-native animation facilities for native and cross-platform
  surfaces. Translate JStack's semantic tokens into that platform's established
  conventions rather than forcing CSS numbers onto every runtime.
- If the required interaction cannot be implemented accessibly and
  interruption-safely with the existing stack, present the dependency need,
  bundle and maintenance cost, alternatives, and rollback impact for explicit
  approval. Never install a library silently.

## Accessibility and performance floors

- Honor `prefers-reduced-motion` or the platform equivalent with explicit
  final-state substitutions. Do not use one global `0.01ms !important` reset
  that leaves delayed events, broken focus, or invisible content.
- Preserve keyboard navigation, visible focus, semantic state, live-region
  announcements, gesture alternatives, and controls for moving or timed
  content. Motion is never the sole status signal.
- Avoid large zoom, parallax, rotational travel, repeated background motion,
  flashing, and high-contrast full-screen transitions that can cause
  vestibular or photosensitive discomfort.
- Prefer opacity and transforms; measure clipping, shadows, filters, masks, and
  large composited layers. Do not animate layout properties in a way that
  causes cumulative layout shift or moves an active target.
- Reuse primitives, cancel superseded animations, and make transitions safe
  under double-clicks, repeated keypresses, route interruption, slow content,
  and unmounting. Do not queue stale transitions.
- Verify representative desktop and mobile hardware. Record dropped-frame or
  long-task evidence when available; never claim "smooth" from visual opinion
  alone.

## Reject generic AI motion

- no scale on every hover;
- no decorative pulse, shimmer, bounce, float, or breathing loop;
- no staggered entrance for ordinary page copy or every list update;
- no universal fade-on-mount for conditional rendering;
- no spring overshoot on menus, form errors, destructive actions, or repeated
  utility controls;
- no animation added only because a library exposes the effect;
- no long transition that hides loading, blocks input, or delays a faster
  direct state change.

## Motion QA report

Report the inventory covered, omitted interactions and reasons, runtime choice
and evidence paths, tokens used, ordinary and reduced-motion behavior tested,
keyboard and focus results, rapid-input and cancellation results, performance
checks, unresolved limitations, and the exact motion-audit outcome. A Beta.5
specification is implementation guidance and never runtime proof. A Beta.6
motion-finalization receipt is exact-candidate evidence only and never release
or deployment authority.

## Beta.6 evidence handoff

The capture harness is host-owned: JStack does not start a browser, simulator,
or native runner. For every specified interaction/platform pair, produce one
`jstack.ui.motion-result.v1` artifact for `ordinary` and one for `reduced`, then
reference those private canonical JSON files from one
`jstack.ui.motion-evidence.v1` manifest. Bind the manifest to the exact clean
candidate Git head, tree, project fingerprint, build digest, runtime digest,
UI contract, motion specification, and producer digest.

The finalizer requires complete untruncated coverage and validates:

- observed properties and measured entrance/exit durations against the
  specified pattern, with no more than one display frame of timing tolerance;
- input feedback at or below 100ms;
- refresh-rate-aware frame budgets, no more than 5% dropped frames, no blocking
  task of 50ms or more, and zero cumulative layout shift;
- rapid-input, interruption, cancellation, reversal, keyboard, visible-focus,
  focus-restoration, semantic-state, and non-motion status behavior; and
- exact reduced-motion substitution, no prohibited repeated or generic motion,
  canonical bounded files, private paths, current timestamps, and stable
  candidate state.

On success JStack writes a deterministic, script-free HTML report beneath the
same private evidence root and returns a candidate-bound receipt. Call
`jstack_ui_finalize` with the original motion-spec receipt and this
motion-finalization receipt as a pair. Static UI work omits both. The report
does not include raw source contents or arbitrary producer prose, and neither
the report nor receipt certifies the capture producer's honesty or subjective
design quality.
