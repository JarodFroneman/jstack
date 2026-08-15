# Accessibility review

Target WCAG 2.2 AA for web and webview surfaces and the target platform's native accessibility semantics for native applications. Automated checks find a subset of problems; combine them with keyboard, assistive-technology, content, and visual inspection.

## Structure and meaning

- Use semantic elements, landmarks, headings, labels, names, roles, values, relationships, and live announcements that match visible behavior.
- Keep reading, focus, and visual order coherent. Give icon-only controls accessible names and expose selected, expanded, busy, invalid, and disabled state.
- Provide text or semantic alternatives for task-critical canvas content and actions.

## Input and navigation

- Complete the critical flow using a keyboard or the platform's equivalent non-pointer input. Make focus visible, non-obscured, logical, and restored after dialogs, menus, navigation, and errors.
- Avoid keyboard traps. Provide a way to bypass repeated content and an alternative to path-based or multi-pointer gestures.
- Use target sizes appropriate to the platform; start with at least 44×44 CSS pixels or iOS points and 48×48 Android dp unless an applicable standard and spacing exception is satisfied.

## Presentation and content

- Meet at least 4.5:1 contrast for ordinary text and 3:1 for large text and meaningful UI graphics or boundaries, subject to the precise WCAG exceptions.
- Do not rely on color, placement, motion, or sound alone. Pair semantic color with text, iconography, pattern, shape, or announced state.
- Verify zoom, text scaling, reflow, long content, localization, dense content, and system contrast settings relevant to the platform. Ensure content is not clipped or hidden behind fixed regions.
- Keep errors specific, associated with the affected field or action, announced when needed, and recoverable without losing valid input.

## Motion and timing

- Honor reduced-motion preferences. Remove nonessential spatial motion, autoplay, parallax, flashing, and repeated animation while preserving state feedback.
- Give users control over meaningful time limits, moving content, and media. Avoid content that flashes more than accessibility thresholds allow.

## Review evidence

Record the tool and version used for automated analysis, the exact routes or screens tested, keyboard and focus results, relevant assistive-technology observations, contrast or text-fit findings, and unresolved limitations. Never describe a surface as accessible solely because an automated scan passed.
