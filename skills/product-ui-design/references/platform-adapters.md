# Platform adapters

Preserve the target platform's interaction conventions, accessibility APIs, safe areas, typography behavior, input methods, and lifecycle. A cross-platform framework does not erase the host platform.

## Web and webviews

- Prefer semantic HTML and native controls, then enhance them without removing keyboard, focus, form, and browser behavior.
- Design for pointer, keyboard, touch, zoom, text scaling, responsive reflow, forced colors where applicable, and reduced motion.
- For webviews, account for host navigation, safe areas, virtual keyboards, offline or bridge failures, and native back behavior. Do not make a webview look native by hiding essential browser semantics.
- Exercise 1440×900, 1280×800, and 390×844 by default; add a tablet viewport when layout or product use makes it relevant.

## iOS and SwiftUI

- Respect safe areas, Dynamic Type, VoiceOver order and labels, native navigation, system gestures, keyboard appearance, and light/dark appearance.
- Use standard controls and symbols already licensed or provided by the project. Provide alternatives for custom canvas gestures and never hide a critical action behind an undiscoverable gesture.
- Test at supported text sizes and orientations relevant to the scoped flow.

## Android and Compose

- Respect system back behavior, window insets, font scaling, TalkBack semantics, touch targets, keyboards, and light/dark appearance.
- Preserve an established Material or product component system. Make focus and keyboard behavior complete for large screens, hardware keyboards, and ChromeOS when those targets are in scope.
- Test configuration changes and interruption or restoration for stateful critical flows.

## React Native

- Use native accessibility roles, labels, state, focus, text scaling, safe-area handling, and platform-specific interactions.
- Share semantic foundations while adapting navigation, controls, gestures, menus, and system feedback per iOS and Android.
- Verify on each claimed host platform; a single simulator screenshot does not prove cross-platform parity.

## Flutter

- Use `Semantics`, platform-aware navigation and controls, text scaling, media padding, focus traversal, shortcuts, and restoration where relevant.
- Preserve an established Material, Cupertino, or product system instead of mixing defaults incidentally.
- Verify each claimed renderer and host platform rather than treating a widget test as runtime visual evidence.

## Electron and Tauri

- Combine web semantics with desktop expectations: resizable windows, minimum sizes, menus, shortcuts, focus restoration, drag regions, file dialogs, offline and failure states, and OS theme changes.
- Keep draggable title regions separate from interactive controls and provide keyboard access to every critical command.
- Test the packaged shell when claiming desktop behavior; browser-only evidence covers the web content, not the host integration.

## Native desktop

- On macOS, Windows, and Linux, follow the product's supported system conventions for menus, windows, dialogs, shortcuts, focus traversal, screen readers, high contrast, density, and scaling.
- Exercise mouse or trackpad and keyboard paths, resizing, multi-window or modal behavior when relevant, and at least the supported minimum window size.
- State the tested OS and runtime. Do not label an adapter qualified without real target-platform evidence.

## Evidence level

Treat the web adapter as qualified only when its required runtime evidence passes. Treat webview, Electron, Tauri, React Native, Flutter, iOS, Android, macOS, Windows, and Linux adapters as contract-only in this protocol version because the v1 manifest cannot independently bind their exact host, packaged, or native runtime provenance. Report the distinction; do not generalize evidence from one framework preview to another platform.

Windows hosts may use routing and session-local contract planning, but Beta.2 UI finalization fails closed because the stdlib-only runtime cannot verify inherited DACL and reparse privacy for evidence files. Begin and finish a release-bound UI lifecycle on a supported POSIX host; do not move a root-bound receipt between machines.
