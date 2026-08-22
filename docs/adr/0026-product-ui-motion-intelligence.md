# ADR 0026: Product UI Motion Intelligence

- Status: Accepted
- Decision date: 2026-08-22
- Target release: 0.10.0-beta.5
- Extends: [ADR 0023](0023-product-interface-system.md)

## Context

The Product Interface System currently defines three broad motion durations and
a reduced-motion floor. That is sufficient to prevent completely arbitrary
timings, but it does not tell an agent which interactions should move, which
should remain instant, how frequency and input mode change the answer, how to
preserve origin and destination, or how to select an implementation technique
without adding a dependency.

The result can still look recognizably machine-generated: every conditional
render fades, every card scales, utility controls bounce, or a static pause is
followed by an abrupt replacement. A larger runtime library would not solve
the decision problem and would impose itself on projects that already have
appropriate platform conventions.

## Research And Licence Boundary

The design review considered `kylezantos/design-motion-principles` at pinned
revision `4a9ca879f24a361f4dca4174fe2da0f67b5ddee3` (MIT). It is a coding-agent
skill with creation and audit guidance, not a runtime animation library.
JStack uses only general ideas such as purposeful motion, interaction-frequency
weighting, continuity, reduced-motion behavior, performance discipline, and
anti-pattern review. The Beta.5 implementation, catalog, schemas, terminology,
examples, and workflow are original. No upstream prompt, persona, example,
file structure, installer, or source code is copied.

If future work copies or adapts MIT material, its copyright and license notice
must be included. Beta.5 introduces no third-party runtime or vendor service.

## Alternatives

1. Expand Markdown guidance only. This is cheap but leaves no strict inventory,
   project binding, deterministic frequency gate, or reusable Beta.6 handoff.
2. Add motion fields to `jstack.ui.contract.v1` or v2. Those schemas are strict
   published contracts; changing them in place would break compatibility and a
   new successor would couple visual scope selection to detailed interaction
   design.
3. Add a runtime animation package to JStack. JStack generates guidance for
   many stacks and platforms, so one web package would be both insufficient and
   an unjustified dependency.
4. Install or fork the research skill. Its assistant-specific structure and
   named design lenses are not JStack contracts, and its audit workflow would
   prematurely combine Beta.5 creation with Beta.6 evidence.
5. Add one internal, canonical-only motion-specification tool bound to the
   existing UI contract. This preserves compatibility, remains deterministic,
   and creates a clean future audit boundary.

## Decision

### Automatic Product UI Design Stage

Product UI Design continues to activate automatically for applicable graphical
interface work. After `jstack_ui_contract` and before source edits, the agent:

1. inspects existing motion code, dependencies, tokens, routing, overlays,
   loading states, and platform conventions;
2. builds a bounded interaction inventory;
3. classifies trigger, purpose, frequency, and input modes;
4. records an explicit omission when instant feedback is more usable;
5. selects one runtime strategy per contracted platform; and
6. calls `jstack_ui_motion_spec` with the existing UI contract receipt.

This is not a seventh slash command and users do not invoke another skill. The
same Product UI Design workflow applies the returned specification.

### Separate Versioned Motion Contract

Add `jstack.ui.motion-catalog.v1`, `jstack.ui.motion-spec.v1`, and a
canonical-only `jstack_ui_motion_spec` tool. Do not add a `gstack_*` alias.
Existing UI contract v1/v2 objects, receipts, finalization, loop, and program
bindings remain unchanged.

The motion tool requires the exact clean baseline represented by a fresh
`jstack_ui_contract` receipt. It binds:

- the current motion catalog digest;
- UI contract schema and digest;
- Git HEAD, project fingerprint, and policy digest;
- selected Product Interface profile per surface;
- one runtime strategy per contracted platform;
- a bounded interaction inventory mapped to contracted surfaces; and
- deterministic token, reduced-motion, interruption, and omission decisions.

It returns a domain-separated durable receipt containing normalized metadata
and digests. The receipt is guidance and a future Beta.6 handoff, not candidate
evidence or execution authority.

### Motion Decisions

Frequency is a first-class constraint:

- rare interactions may use restrained spatial continuity up to 320ms;
- routine interactions use state or spatial tokens up to 240ms;
- frequent interactions are capped at 120ms and lose nonessential travel,
  stagger, blur, and spring behavior; and
- continuous interactions follow input directly, with a short settle only
  after release when needed.

The catalog covers controls, navigation and routes, tabs, overlays, menus,
tooltips, disclosure, cards and lists, reordering, forms, loading and content
replacement, notifications, icon transitions, shared elements, and gestures.
Every category defines purpose, allowed properties, entrance and exit tokens,
optional spring character, spatial bounds, reduced-motion substitution, and
reversibility.

The shared tokens include multiple duration tiers, distinct easing roles,
restrained spring characters, distance and scale bounds, opacity, measured blur
ceilings, stagger limits, overlay behavior, and explicit reduced-motion floors.
There is deliberately no universal duration or spring.

### Runtime Policy

Runtime selection is per platform. `existing` requires hashed evidence from
tracked repository files. `auto` resolves to CSS for web-like platforms and
platform-native facilities elsewhere. CSS, View Transitions, and
platform-native selections are permitted only on compatible platform classes.
The tool never installs a dependency and the specification always records
`dependencyAdded=false`.

An agent may recommend another library only outside the tool after explaining
why existing/native facilities are insufficient, showing bundle and
maintenance impact, alternatives, and rollback, and obtaining explicit user
approval. Beta.5 does not make that dependency decision automatically.

### Accessibility And Performance

Every specified interaction has a reduced-motion result that preserves visible
and semantic state. Motion cannot be the sole signal. Focus, announcements,
gesture alternatives, and target stability remain mandatory.

The catalog prefers opacity and transforms, bounds distance, scale, blur, and
stagger, forbids cumulative layout shift, and requires cancellation under rapid
input. Clipping, filters, shadows, masks, and large composited layers require
measurement. Smoothness cannot be claimed from visual opinion alone.

### Security And Privacy

- Public tool input and motion output schemas are closed and bounded.
- Interaction and runtime rows reject unknown fields, duplicate identifiers,
  unsupported enums, invalid surface mappings, and oversized text or arrays.
- Runtime evidence must be a safe, tracked, stable regular repository file.
- Evidence paths and runtime rationale are replaced by SHA-256 digests before
  entering the specification or receipt.
- Receipts contain no source file contents, screenshots, credentials, secrets,
  hidden reasoning, or signing material.
- The motion receipt uses a domain-separated key derived from the existing
  private UI contract key and has the same bounded freshness window.
- The tool is read-only: it performs no edit, dependency installation, model or
  network call, Git mutation, release, deployment, external action, or
  production change.

## Beta.6 Boundary

Beta.5 specifies creation-time intent and supplies a future audit binding. It
does not capture runtime animations, calculate frame performance, create an
HTML motion report, compare implementation with the specification, or issue a
pass/fail motion finalization receipt. Those independent verification
capabilities remain Beta.6 work.

## Compatibility And Rollback

The live MCP grows from 57 to 58 canonical tools while all 52 `gstack_*`
aliases and all six workflow names remain frozen. Existing UI contract v1/v2
bytes and semantics do not change. The new module, schema, catalog, tool,
receipt domain, skill reference, and generated mirrors can be removed together
without migrating existing contracts or persisted state.

Rollback to Beta.4.1 removes motion-spec creation and returns Product UI Design
to its prior three-duration guidance. Any Beta.5 motion receipt becomes invalid
when the server version or motion catalog changes.

## Consequences

Applicable UI work gains a deterministic motion brief without imposing an
animation runtime or questionnaire on static work. Agents must perform one
additional internal tool call and inventory meaningful interactions before
editing. Beta.5 improves the consistency of creation guidance but makes no
claim of measured design uplift or runtime correctness until evaluation and
the deferred Beta.6 audit produce evidence.
