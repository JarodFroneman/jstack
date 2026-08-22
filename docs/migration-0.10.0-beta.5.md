# Migrating to JStack 0.10.0-beta.5

Beta.5 adds Product UI Motion Intelligence to the existing automatic Product
UI Design workflow. It does not add a slash command or install an animation
runtime in JStack or user projects.

## What changes

- The MCP surface grows from 57 to 58 canonical tools with
  `jstack_ui_motion_spec`.
- All 52 frozen `gstack_*` aliases and all six command names remain unchanged.
- Product UI Design now creates a bounded interaction inventory after
  `jstack_ui_contract` and before UI source edits.
- The new `jstack.ui.motion-spec.v1` contract binds frequency, input modes,
  surface profiles, runtime strategy, motion tokens, omission reasons, and
  reduced-motion behavior to the existing UI contract baseline.
- UI contract v1 and v2, candidate finalization, loop/program bindings, and
  persisted state remain backward compatible.

## Automatic workflow

For applicable interactive UI work:

1. inspect the project and obtain the normal `jstack_ui_contract`;
2. inventory meaningful controls, routes, overlays, disclosure, loading,
   notifications, list changes, direct manipulation, and other transitions;
3. classify each as rare, routine, frequent, or continuous and record pointer,
   touch, keyboard, or gesture input;
4. select one repository-grounded runtime strategy per contracted platform;
5. call `jstack_ui_motion_spec`; and
6. implement the returned specification with explicit reduced-motion behavior.

Static presentation-only work does not need a motion inventory. High-frequency
and keyboard-driven actions may intentionally use instant state changes.

## Runtime dependencies

Beta.5 adds no third-party package. Existing project motion facilities take
precedence. Otherwise the deterministic `auto` strategy selects CSS for
web-like platforms and platform-native facilities elsewhere. View Transitions
must be selected deliberately. A new animation library still requires a
separate evidence-backed user decision and is never installed automatically.

## Evidence boundary

The motion-spec receipt is creation guidance and a future Beta.6 handoff. It is
not candidate evidence, runtime proof, a Product Interface finalization
receipt, or release/deployment permission. Independent runtime capture,
performance assessment, report generation, and pass/fail motion audit remain
deferred to Beta.6.

## Validation

After installing the release candidate, verify:

1. MCP version `0.10.0-beta.5`;
2. 58 canonical tools and 52 frozen aliases;
3. `jstack_ui_motion_spec` is present and `gstack_ui_motion_spec` is absent;
4. Product UI Design contains `references/motion-intelligence.md`;
5. `ui-motion-spec.v1.schema.json` is installed with the MCP; and
6. ordinary UI contract v1/v2 fixtures still validate unchanged.

## Rollback

Restore the prior Beta.4.1 plugin and MCP distribution. Existing UI contracts
and persisted state require no migration. Beta.5 motion receipts are expected
to invalidate when the server or motion catalog version changes.
