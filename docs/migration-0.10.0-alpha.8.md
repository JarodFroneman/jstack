# Migrating To JStack v0.10.0-alpha.8

JStack v0.10.0-alpha.8 implements Phase 7 of the verified Audit Mastery
roadmap: Dynamic and Adversarial Verification.

## What Changed

- Audit curriculum content version is now 9.
- Stage 7 uses the closed `jstack.adversarial.capture.v1` and
  `jstack.audit.adversarial-verification.v1` contracts.
- The new `jstack_adversarial_capture` tool raises the canonical MCP inventory
  from 51 to 52 tools.
- Stage 7 accepts only `adversarial-plan.md`, `verification-results.json`, and
  `false-positive-analysis.md` at their exact `.jstack-training/` paths.
- Captures require at least four cases across at least three categories, with
  exactly two identical classified outcomes for every case.
- The result must classify all eight categories, map every case to exactly one
  static or dynamic hypothesis, contain confirmed and refuted dispositions,
  and provide exactly one reciprocal supported or false-positive assessment
  for every hypothesis.
- Every discovered QA command needs a current passing receipt, and the
  candidate needs a current complete passing security receipt.
- The audit drill uses one current capture. The harness drill verifies a
  separately committed strict-ancestor change with exact paths, at least one
  added case, no removed cases, and stable shared contracts and outcomes.

## Capture Boundary

Discovery is read-only. Capture execution is a normal internal tool handoff
inside a separately authorized trusted development or QA workflow. JStack
binds execution to the exact reviewed Git state; the user does not copy a
token, signing command, challenge, or confirmation digest into a terminal.

The local runner uses a scrubbed environment, isolated HOME, closed stdin,
timeouts, and bounded output, but it is not an OS or network sandbox and
retains the current user's filesystem and network privileges. Use an
externally enforced container or VM for untrusted repositories or active
security testing. The capture classification `none-observed` does not prove
that external effects were prevented.

## Compatibility

- The five public commands are unchanged.
- Mastery profile schema v3 is unchanged. Existing attempts retain their
  original curriculum digest; new Stage 7 attempts bind curriculum version 9.
- Python 3.9+ and the standard-library-only MCP runtime remain supported.
- Legacy `gstack_*` aliases remain available.
- Existing Stage 0 through Stage 6 evidence contracts are unchanged.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.8` tag.
2. Back up the current MCP, plugin sources/caches, Codex configuration, and
   `~/.jstack` state.
3. Run `python3 scripts/validate_skills.py`,
   `python3 scripts/sync_artifacts.py --check`, and
   `python3 -m unittest discover -s tests -v`.
4. Run `python3 scripts/install.py` for the shared Codex installation or
   reinstall the five dedicated plugins from the personal marketplace.
5. Restart Codex.
6. Verify the MCP initialize response reports `0.10.0-alpha.8`, `tools/list`
   exposes 52 canonical tools including `jstack_adversarial_capture`, all five
   plugins report the same version, and the umbrella plugin remains
   uninstalled when using the dedicated layout.

## Meaning Of A Pass

A Stage 7 pass proves bounded Git, campaign, receipt, deterministic-rerun,
hypothesis, false-positive, category, QA, security, and comparison protocol
integrity. It does not prove vulnerability absence, exploitability, zero-day
detection, universal behavior, remediation safety, release readiness,
production safety, or production authority.
