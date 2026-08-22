# ADR 0027: Product UI Motion Enforcement And Evidence Gates

- Status: Accepted
- Decision date: 2026-08-22
- Target release: 0.10.0-beta.6
- Extends: [ADR 0023](0023-product-interface-system.md) and
  [ADR 0026](0026-product-ui-motion-intelligence.md)

## Context

Beta.5 creates a deterministic, UI-contract-bound motion specification before
implementation. It deliberately does not prove that a candidate implemented
that specification, exercised reduced motion, responded immediately, survived
interruption, or met runtime performance floors. Informal QA prose would leave
those claims unbound to the exact candidate and could be copied between builds.

JStack also cannot assume that every supported host exposes the same browser,
simulator, native instrumentation, or signed measurement service. Embedding a
Playwright runtime in the MCP would add a large dependency and would still not
cover native platforms. Beta.6 therefore needs a strict boundary between
host-owned measurement and offline deterministic validation.

## Alternatives

1. Keep motion verification as skill guidance. This preserves portability but
   provides no complete coverage check, byte binding, candidate binding, or
   reusable downstream receipt.
2. Make `jstack_ui_finalize` parse motion evidence directly. This avoids one
   tool but makes the existing finalizer larger, mixes screenshot and temporal
   contracts, and forces static callers through motion-specific fields.
3. Add a capture/finalize tool pair. A capture tool would falsely imply that
   the portable MCP can operate every host runtime and would duplicate browser
   or native harness responsibilities.
4. Install Playwright or an animation library in JStack. Neither is necessary
   for deterministic validation, and a web-only runtime would not cover the
   existing multi-platform Product Interface contract.
5. Add one canonical-only motion finalizer that consumes bounded host-produced
   evidence and optionally binds its receipt into the existing UI finalizer.
   This separates trust boundaries, preserves static compatibility, and keeps
   the core standard-library-only.

## Decision

### One Offline Finalization Tool

Add canonical-only `jstack_ui_motion_finalize`; do not add a `gstack_*` alias
or another slash command. Product UI Design invokes it automatically when a
Beta.5 motion specification applies. The tool:

1. validates the exact motion-specification receipt without treating it as
   candidate evidence;
2. requires a clean, substantive descendant of the specification baseline;
3. binds the current Git head, tree, project fingerprint, policy, build digest,
   and runtime digest;
4. reads one canonical manifest and all referenced result artifacts from the
   existing private UI evidence root;
5. performs two independent deterministic reads and rejects changed evidence;
6. rechecks candidate stability before and after report creation;
7. writes one idempotent private HTML report; and
8. issues a short-lived session receipt with no execution authority.

The tool performs no browser or native capture, model call, network request,
project edit, dependency installation, Git mutation, release, deployment,
external action, or production change. Its `readOnlyHint` is false only because
it creates the private report artifact.

### Closed Evidence Contracts

Add four Draft 2020-12 schemas:

- `jstack.ui.motion-result.v1` describes one interaction, platform, and motion
  mode measurement;
- `jstack.ui.motion-evidence.v1` binds the complete result set, producer, exact
  candidate, UI contract, and motion specification;
- `jstack.ui.motion-audit.v1` is JStack's normalized deterministic audit; and
- `jstack.ui.motion-finalization.v1` is the public finalizer response.

Objects are closed and bounded. Manifests and result artifacts must be UTF-8
canonical JSON plus one newline, private regular files reached by safe relative
paths, no older than 24 hours, and digest- and size-matched. The manifest is at
most 8 MB; each result is at most 1 MB; aggregate reads are at most 250 MB; and
the closed maximum is 2,816 results.

Every motion-specification interaction and platform requires exactly one
`ordinary` and one `reduced` result. Duplicate, missing, extra, truncated,
unknown-field, stale, non-canonical, unsafe-path, symlink, mismatched-candidate,
or mismatched-artifact evidence fails closed.

### Deterministic Enforcement

The finalizer compares declared observations with the exact Beta.5 pattern:

- observed properties must be permitted by the ordinary or reduced pattern;
- entrance and exit duration must match the semantic duration token within one
  measured display frame;
- distance, scale, and blur cannot exceed their specified token bounds;
- intentionally omitted interactions must remain instant;
- reduced mode must use the specified substitution and remove spatial, scale,
  and blur motion;
- meaningful input feedback must occur within 100ms;
- the frame budget must match the measured refresh rate within 1ms;
- dropped frames cannot exceed 5%, blocking long tasks are forbidden at the
  50ms threshold, and cumulative layout shift must be zero; and
- rapid input, interruption, cancellation, reversal, keyboard operation,
  visible focus, focus restoration, semantic state, non-motion status clarity,
  bounded repetition, and the anti-pattern check must all pass.

These are contract floors, not a claim that every platform exposes perfectly
equivalent instrumentation. A producer must decline or fail a result it cannot
measure honestly; it must not fabricate a pass.

### Private Report

The report is derived only from normalized safe fields. It has a restrictive
content security policy, no script, network resource, image, media, object, or
form capability, and contains no arbitrary producer prose or source content.
Its deterministic path is based on the audit digest, writes use exclusive
creation and no-follow protections where available, and the final file must be
a private regular file. Repeating the same audit reuses identical bytes.

The report explicitly states that JStack validates bounded bytes and declared
measurements but does not certify producer honesty, semantic truth, subjective
aesthetic quality, complete accessibility, release readiness, or deployment
safety.

### Integration With UI Finalization

Add two optional paired inputs to `jstack_ui_finalize`:
`motion_spec_receipt` and `motion_finalization_receipt`. Motion-applicable work
must supply both; static work supplies neither. When present, the existing UI
finalizer independently verifies:

- the motion specification binds the same UI contract baseline;
- the motion receipt binds the exact current candidate, build, runtime,
  specification, policy, audit, report, and evidence manifest; and
- the receipt is complete, passing, current-session evidence with
  `executionAuthorized=false`.

The resulting opaque UI receipt includes motion specification, audit, report,
manifest, and finalization-receipt digests. The public
`jstack.ui.finalization.v1` response schema remains unchanged, so existing
static callers and downstream loop, program, and release consumers continue to
use the same UI receipt contract.

## Enforcement Boundary

The MCP enforces schema closure, path and file safety, byte digests, candidate
binding, coverage, deterministic comparisons, report bytes, receipt binding,
and invalidation. The host skill enforces that motion-applicable work actually
runs the capture harness and supplies both receipts to UI finalization.

JStack cannot intercept arbitrary Codex or third-party host actions that bypass
its commands and tools. It cannot independently prove that a measurement
producer observed the claimed UI, that user-authored instrumentation is honest,
or that the interface is aesthetically excellent. The audit and response mark
producer-honesty and semantic-truth certification false.

## Security And Privacy

- The evidence root inherits the existing Product Interface authority, owner,
  mode, ancestor, regular-file, symlink, and byte-limit checks.
- Source files, screenshots, raw prompts, source contents, secrets,
  credentials, signing material, and hidden reasoning are not returned or
  copied into receipts or reports.
- Build, runtime, result, path, producer, manifest, audit, report, candidate,
  contract, and specification bindings use SHA-256 digests.
- Unknown fields, unbounded arrays, invalid numbers, NaN/infinity, control
  characters, stale timestamps, mismatched self-digests, incomplete evidence,
  and changed reads fail closed.
- There is no network or model fallback. Failure produces no passing receipt.
- The finalization receipt grants no implementation, Git, release, deployment,
  external-action, or production authority and does not replace QA, security,
  screenshot evidence, Product observations, or human approval.

## Compatibility And Rollback

The live surface grows from 58 to 59 canonical tools. All 52 compatibility
aliases and six command names remain unchanged. UI contract v1/v2,
`jstack.ui.motion-spec.v1`, `jstack.ui.finalization.v1`, persisted loop/program
state, and ordinary static UI finalization remain compatible. The only existing
request change is the additive paired optional motion inputs on
`jstack_ui_finalize`.

Beta.5 motion receipts contain the prior server version and are intentionally
invalid after upgrade; recreate the UI contract and motion specification under
Beta.6 before producing candidate evidence. Rollback restores the complete
Beta.5 MCP/plugin unit. Beta.6 finalization receipts then become invalid, while
existing project and persisted workflow state requires no migration. Private
reports may be retained for audit or removed separately by their owner.

## Consequences

Motion-applicable Product UI work gains a reproducible candidate gate without a
new runtime dependency or user-facing command. It costs two result artifacts
per interaction/platform pair plus capture and validation time. Static work is
unchanged. The result is materially stronger evidence of contract conformance,
but the trust in the external capture producer remains explicit rather than
being overstated.
