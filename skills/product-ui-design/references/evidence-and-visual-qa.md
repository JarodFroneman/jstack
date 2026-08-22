# Evidence and visual QA

Verify the candidate that will be delivered, not a stale development state. In JStack, let the issued UI contract define the exact evidence matrix and let the finalizer validate its bounded manifest; do not substitute an informal checklist for that contract.

## Build the matrix

- Enumerate each scoped surface, exact route or locator, target platform, supported theme, required viewport, and applicable state.
- For web, include 1440×900, 1280×800, and 390×844 by default, plus a tablet viewport when relevant.
- Capture `normal` at every required viewport for each surface/platform/theme. Capture each other applicable state at the contract's designated primary viewport; this is the bounded v1 matrix, not an unstated Cartesian expansion.
- Cover applicable loading, empty, error, disabled, focused, selected, success, and destructive states. Put every other v1 state in `stateExclusions` with a concrete reason rather than omitting it silently.
- Exercise every critical flow, including recovery from meaningful failures. Include keyboard and focus, accessibility, reduced motion, and text-fit or overflow results for every surface/platform, and bind each aggregate result to the exact contracted matrix cells it covered.

## Capture visual evidence

- Capture fully opaque, metadata-free 8-bit RGB or RGBA PNG screenshots from the exact runtime state named by the matrix. Record route or locator, state, theme, platform, viewport dimensions, device-pixel ratio, file digest, and capture time.
- Use fixture accounts, synthetic data, and test identities. Do not capture production secrets or personal data. Keep evidence local unless the user explicitly approves another destination.
- Strip unnecessary metadata and reject placeholders, stale captures, wrong dimensions, mismatched hashes, missing files, or evidence transplanted from another repository state.
- When matching a source, compare the source and candidate together at the same viewport and state. A screenshot viewed alone does not establish fidelity.

## Inspect like a product reviewer

- Check hierarchy, information grouping, alignment, spacing rhythm, type roles and weights, borders, radii, elevation, icon quality, image crop, density, and theme coherence.
- Check every required viewport for overlap, clipping, off-canvas controls, unsafe truncation, unintended scroll, layout shift, and awkward empty or dense states.
- Check interaction feedback, target stability, selection clarity, focus visibility, error recovery, responsive transitions, and reduced-motion behavior.
- Record Product or UX observations as pass, advisory, or blocker with the exact surface and evidence. Use the published `ui-product-observation.v1` artifact; use the published `ui-objective-result.v1` artifact (including digest-bound structured assertion measurements) for objective checks. Human visual approval is optional unless the user or release policy requires it.

## Exercise and finalize the motion specification

- Revisit every `jstack_ui_motion_spec` inventory item at runtime. Confirm its trigger, visible feedback, final state, origin and destination where applicable, exit behavior, and explicit omission reason.
- Exercise ordinary and reduced-motion modes, keyboard and pointer or touch input, rapid repetition, cancellation, back navigation, interrupted routes, slow content, and unmounting. Focus, target geometry, and semantic state must remain stable.
- Check that transforms, opacity, clipping, filters, and composited layers do not create cumulative layout shift, stale transitions, long tasks, dropped frames, or an input-blocking pause on representative desktop and mobile hardware.
- Report the runtime strategy actually used and any divergence from the specification. Encode every interaction/platform ordinary and reduced result using the published private canonical contracts, then call `jstack_ui_motion_finalize`. A divergence, missing mode, stale or tampered artifact, failed semantic/accessibility assertion, performance-budget breach, or changed candidate blocks the motion receipt.

## Finalize honestly

- Block completion when required evidence is absent, the Git candidate drifted, a screenshot digest or dimension fails, a critical flow or accessibility check fails, target-platform coverage is missing, or a clipping or overlap blocker remains.
- Treat a valid receipt as proof that named evidence was bound to a particular goal, catalog, repository baseline, and clean candidate. It does not prove that the evidence producer was honest or that aesthetics are objectively excellent.
- Keep result, assertion, observation, and screenshot bytes private beneath the server-selected evidence root. The public receipt returns only normalized counts and digests.
- When motion applies, pass the original motion-spec receipt and the exact-candidate motion-finalization receipt together to `jstack_ui_finalize`. Static work passes neither. The paired receipts bind motion evidence into UI evidence but do not replace QA, screenshot coverage, Product observations, accessibility review, release checks, or human authority.
- Outside JStack, report the same matrix and checks in the handoff, but do not imply that local notes are a signed finalization receipt.
