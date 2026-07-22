# Migrating To JStack 0.8

JStack 0.8 adds mandatory applicability-aware launch assurance for production
release readiness. It upgrades the existing five commands and retains the v0.7
local-only external-action boundary.

## Before upgrade

1. Back up the installed MCP, five plugins, optional umbrella plugin, Codex
   configuration, and `~/.jstack/` state.
2. Finish or intentionally stop active release-readiness work. Existing QA,
   security, audit, loop, and program records remain readable, but all signed
   receipts are session/version-bound and must be regenerated after restart.
3. Record the installed version and canonical tool inventory.
4. Validate the 0.8 checkout before installation.

## Behavioral changes

- The MCP exposes 53 canonical tools: the prior 50 plus
  `jstack_launch_assess`, `jstack_launch_evidence_register`, and
  `jstack_launch_finalize`.
- Production `jstack_release_readiness` requires `launch_receipt` from the exact
  clean release candidate.
- Every launch profile explicitly declares `core` and all applicable surfaces.
- Missing, failed, incomplete, duplicate, stale, or drifted blocker/required
  launch evidence prevents readiness.
- Blockers cannot be waived. Eligible required waivers are bounded structured
  records and can be disabled by policy.
- `public-web`, `commercial`, `payments`, and `regulated-data` profiles require
  a current release-profile audit by default.
- The capability catalog grows from 14 to 18 packs with web launch, email
  deliverability, product observability, and privacy/legal evidence methods.
- Release readiness still returns `executionAuthorized=false`.

Local development that is not a production readiness assessment does not need
a launch receipt. Artifact-only projects still cannot obtain Git-bound JStack
release certification.

## Policy migration

Add the `launch` section from `mcp/jstack/templates/jstack.enterprise.json`.
Repositories without the section receive the built-in production floor, so
omission does not preserve 0.7 behavior. Project policy may strengthen but not
weaken the floor.

The `requiredChecks` list now includes
`launch_assurance_for_production`. The enforceable behavior comes from the
typed `launch` policy and receipt validator, not from the name alone.

## Release workflow migration

1. Commit the complete release candidate and choose an explicit pre-release
   `base_ref`.
2. Call `jstack_launch_assess` with `core`, every applicable surface, target
   environment and URL where required, owner, and reference.
3. Gather safe evidence outside JStack where provider, browser, device, DNS,
   email, legal, payment, or production interaction is needed.
4. Register one bounded artifact per evidenced control.
5. Resolve all blocker and required controls and call
   `jstack_launch_finalize`.
6. Pass `launchReceipt` to `jstack_release_readiness` together with current QA,
   security, and any required release-audit receipt.
7. Treat readiness as evidence only. Each commit, push, pull request, merge,
   tag, release, deploy, or production mutation still needs its own v0.7-style
   signed one-time authorization.

## Verify

Run:

```bash
python3 scripts/sync_artifacts.py --check
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

After installation and restart, verify `serverVersion` is `0.8.0`, tools/list
contains 53 canonical `jstack_*` tools, the three launch tools are present, and
all five installed plugin versions share the same 0.8.0 base version.

Use only disposable local fixtures to test receipt invalidation and release
gates. Do not generate real charges, production webhooks, provider mutations,
or external publication merely to prove the protocol works.

## Rollback

Restore the 0.7 MCP, all five plugin versions, optional umbrella plugin, and
Codex configuration as one release unit, then restart Codex. Do not mix 0.7
skills with the 0.8 MCP.

Treat all 0.8 launch sessions, evidence receipts, final receipts, and
release-readiness results as expired after rollback. Preserve external evidence
artifacts privately if needed for audit history, but recollect and re-register
them before a future 0.8 release assessment.
