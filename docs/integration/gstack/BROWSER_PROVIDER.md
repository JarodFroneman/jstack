# Stage 11 — Browser Provider

## Status and authority

| Item | Value |
| --- | --- |
| Program stage | Stage 11 — Browser Provider |
| Authoritative requirements | `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md`, Browser Provider and Stage 11 sections |
| JStack baseline | `49cf545d940c43b394ea35ed78b5ab5742d7bcf7` |
| gstack baseline | `ad8400543cd9ce8d07641362db48d44a95417e33`, tree `993294b0a09f5265d2d5af6d2fb8234ae2efe450`, version `1.69.0.0` |
| Adaptation | Original JStack protocol and project-script adapter; no upstream runtime or prompt copied |
| Authority effect | None |
| Advance gate | **PASS** — provider cannot write source or deploy implicitly |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

Stage 11 adds one optional canonical-only `jstack_browser_capture` tool. It
discovers browser-oriented `package.json` scripts and, after explicit trusted
execution approval, may run exactly one through JStack's existing scrubbed,
bounded command runner. It does not vendor or invoke gstack's Bun/Playwright
runtime, browser state, cookies, tunnel, model, installer, updater, telemetry,
or control plane.

## Pinned upstream review

The provider design was informed by the pinned MIT-licensed browser lifecycle,
skill-command, content-boundary, security, URL-validation, and QA sources:

- `browse/src/browser-manager.ts`;
- `browse/src/browser-skill-commands.ts`;
- `browse/src/content-security.ts`;
- `browse/src/security.ts`;
- `browse/src/url-validation.ts`; and
- `qa/SKILL.md.tmpl`.

Only general architecture and risk lessons were re-expressed. No TypeScript,
prompt wording, executable, dependency, state file, browser profile, cookie,
or automatic-remediation behavior is copied. The immutable provenance record
is `gstack-browser-provider-adaptation` with adaptation type `WRAPPED` and
disposition `B`.

## Provider boundary

```text
read-only discovery
  → exact package.json browser script + fingerprint
  → explicit trusted-local-execution approval
  → exact Git/policy/candidate/build/runtime/scenario binding
  → scrubbed bounded project-script execution
  → closed digest-only result validation
  → mutation/freshness/completeness checks
  → passing or failing browser-evidence receipt
```

The initial provider kind is `project-script`. `host-native` and
`gstack-browser` remain recognized contract categories but are not selected,
installed, or executed. Missing npm, missing scripts, unsupported hosts, and
provider errors are reported truthfully; there is no silent fallback.

Routes are limited to application-relative paths and credential-free
localhost HTTP(S) URLs. Query strings, fragments, traversal, credentials, and
external origins are rejected. External navigation requires a separately
authorized future host provider and is not available in Stage 11.

## Closed evidence protocol

`jstack.browser-provider-result.v1` binds:

- provider ID, kind, version, host, independence claim, and capabilities;
- Git HEAD, project fingerprint, build digest, and runtime digest;
- scenario ID, local route, viewport, device-pixel ratio, and motion mode;
- ordered interaction steps and assertions;
- digest-only artifacts and console, network, and accessibility observations;
- outcome, completeness, truncation, duration, errors, and observation time;
- an evidence digest and immutable zero-authority declaration.

Passing evidence must be complete, untruncated, current, candidate-matched,
and free of failed steps/assertions, console errors, network failures, policy
failures, critical accessibility violations, or protocol errors. A structured
failure may receive a failing receipt so remediation can cite exact evidence.
Blocked/error evidence cannot claim complete coverage.

Unknown fields, duplicate JSON keys, stale evidence, symlinked or changing
output files, oversized output, provider/host drift, candidate drift, and
unsupported values fail closed. The normalized response excludes raw page
content and command stdout/stderr.

## Execution and authority limits

The runner closes stdin, uses argv without a shell, forwards no host secrets,
uses an isolated HOME, caps output, bounds time, and terminates the process
group. It still runs repository-controlled code with the current user's
filesystem and network privileges. It is explicitly not an OS or network
sandbox.

The contract and receipt fix all of these to false: source write, Git write,
release, deployment, and production mutation. `authorityEffect` is `none`.
Repository mutation during capture invalidates the pass and suppresses the
receipt. Browser QA cannot fix a finding; Stage 12 owns the separately
authorized QA-to-Builder remediation handoff.

## Compatibility and rollback

The public surface is six commands, 60 canonical tools, and 52 frozen aliases.
There is no `gstack_browser_capture` alias and no new command, role, model,
dependency, or production action. Canonical provider and schema files mirror
into the umbrella plugin through `scripts/sync_artifacts.py`.

Rollback removes the one canonical tool, provider package, two schemas,
reference, tests, and provenance record. Existing QA, Product Interface,
motion, audit, release, and frozen compatibility surfaces remain intact.

## Advance gate

Stage 11 may pass only when focused and repository gates prove:

1. discovery is deterministic and read-only;
2. script text never becomes shell argv;
3. external/traversal/credential-bearing scenarios are rejected;
4. provider, host, candidate, build, runtime, and scenario mismatches fail;
5. pass claims reject truncation and every structured failing signal;
6. duplicate, stale, symlinked, changing, and oversized output fails closed;
7. repository mutation suppresses the receipt;
8. raw command output is excluded from the response;
9. the tool is canonical-only and the alias count remains frozen; and
10. sync, schema, compatibility, provenance, compile, and product-boundary
    checks remain green.

The Stage 11 focused gate passed 35 tests with one declared optional-schema
skip, plus contract compatibility, sync, immutable 761-file/11-record
provenance, Python compilation, product boundaries, and `git diff --check`.

No Stage 11 result authorizes a commit, push, release, deployment, global
installation, provider fallback, or production action.
