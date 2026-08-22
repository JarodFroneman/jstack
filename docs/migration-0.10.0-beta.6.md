# Migrating to JStack 0.10.0-beta.6

Beta.6 adds Product UI Motion Enforcement to the existing automatic Product UI
Design workflow. It adds no slash command, browser runtime, animation package,
or deployment authority.

## What changes

- The MCP surface grows from 58 to 59 canonical tools with
  `jstack_ui_motion_finalize`.
- All 52 frozen `gstack_*` aliases and all six command names remain unchanged.
- Four closed schemas describe private runtime results and manifests,
  deterministic audits, and finalization responses.
- Motion-applicable UI candidates now require ordinary and reduced-motion
  result coverage before ordinary UI finalization.
- `jstack_ui_finalize` accepts the motion-spec and motion-finalization receipts
  as a paired optional input. Static UI work omits both and behaves as before.
- UI contract v1/v2, motion specification v1, UI finalization v1, loop/program
  bindings, and persisted state remain backward compatible.

## Automatic workflow

For applicable interactive UI work:

1. obtain `jstack_ui_contract` on the clean baseline;
2. inventory interactions and obtain `jstack_ui_motion_spec` before edits;
3. implement and verify the specification, including reduced motion;
4. commit a clean substantive candidate and produce the normal passing QA and
   UI evidence;
5. use the selected host browser or native harness to create one canonical
   `jstack.ui.motion-result.v1` artifact for each interaction/platform in
   ordinary and reduced mode, plus one `jstack.ui.motion-evidence.v1` manifest
   beneath the private UI evidence root;
6. call `jstack_ui_motion_finalize` with the exact specification receipt,
   manifest path, build digest, and runtime digest; and
7. call `jstack_ui_finalize` with its existing inputs plus the original
   motion-spec receipt and the passing motion-finalization receipt.

The MCP does not start the capture harness. A host that cannot produce honest
measurements must report the limitation and cannot claim a passing Beta.6
motion audit.

## Evidence thresholds

The candidate gate requires complete ordinary and reduced coverage, durations
within one measured display frame of the specified tokens, input feedback no
slower than 100ms, a refresh-rate-aware frame budget, no more than 5% dropped
frames, no blocking long task at or above 50ms, and zero cumulative layout
shift. Rapid input, interruption, cancellation, reversal, keyboard and focus
behavior, semantic state, reduced-motion substitution, non-motion status
clarity, and anti-pattern checks must pass.

On success, JStack writes a deterministic script-free HTML report beneath the
private evidence root. The report and receipt validate the named bytes and
declared measurements for one exact candidate. They do not prove producer
honesty, aesthetic quality, complete accessibility, release readiness, or
production safety.

## Receipt invalidation

Beta.5 motion-spec receipts are server-version-bound and cannot be reused under
Beta.6. Recreate the UI contract and motion specification after upgrade, then
capture the candidate evidence. Any change to Git head/tree, project
fingerprint, policy, UI contract, motion specification/catalog, build digest,
runtime digest, evidence bytes, server session, or receipt expiry invalidates
the relevant finalization binding.

## Validation

After installing the release candidate, verify:

1. MCP version `0.10.0-beta.6`;
2. 59 canonical tools and 52 frozen aliases;
3. `jstack_ui_motion_finalize` is present and
   `gstack_ui_motion_finalize` is absent;
4. `jstack_ui_finalize` exposes both paired optional motion receipt fields;
5. `ui-motion-result.v1.schema.json`, `ui-motion-evidence.v1.schema.json`,
   `ui-motion-audit.v1.schema.json`, and
   `ui-motion-finalization.v1.schema.json` are installed with the MCP;
6. Product UI Design documents the automatic motion finalization handoff; and
7. ordinary static UI finalization fixtures still pass unchanged.

## Rollback

Restore the complete Beta.5 plugin and MCP distribution as one unit. Existing
UI contracts and persisted loop/program state require no data migration.
Beta.6 motion-finalization receipts are expected to invalidate after rollback.
Private reports can remain as inert audit artifacts or be removed separately by
their owner.
