# Stage 12 — Browser QA and Remediation Handoff

## Status and authority

| Item | Value |
| --- | --- |
| Program stage | Stage 12 — Browser QA & Remediation Handoff |
| Authoritative requirements | `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md`, sections 8.2, 25, and Stage 12 |
| Execution wrapper | Attached Final Codex Master Prompt, Browser Provider, QA Remediation, and Core Invariants sections |
| JStack baseline | `49cf545d940c43b394ea35ed78b5ab5742d7bcf7` |
| gstack baseline | `ad8400543cd9ce8d07641362db48d44a95417e33`, tree `993294b0a09f5265d2d5af6d2fb8234ae2efe450` |
| Authority effect | None; the handoff narrows execution to the original scoped writer |
| Advance gate | **PASS** — QA/Builder boundaries hold |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

Stage 12 extends the existing Team Composer dispatch gate and Stage 11 browser
tool. It adds no command, canonical tool, alias, role, provider runtime,
dependency, or independent action path.

## Required state transition

```text
read-only Browser QA
  → complete current-candidate failing receipt
  → structured finding with sourceMutationAttempted=false
  → existing Team Plan authority check
  → original scoped Builder only
  → changed project fingerprint and rebuilt candidate
  → prior browser evidence stale
  → same-scenario fresh re-QA
  → fresh pass resolves / fresh fail remains open
```

QA may recommend remediation. It never acquires Builder, Git, release,
deployment, production, or external-action authority. The remediation slice
contains exactly the one assignment that already owned the Team Plan's bounded
write scope. Browser QA must remain a read-only assignment on a different
physical agent. If either condition is absent, dispatch fails closed.

## Finding contract

`jstack.browser-finding.v1` is published at
`mcp/jstack/schemas/browser-finding.v1.schema.json`. It requires a portable ID,
category, severity, title, claim, distinct expected/observed behavior,
reproduction state, recommendation, sorted evidence references, exact browser
evidence and scenario digests, and `sourceMutationAttempted=false`.

The normalized response may display the finding to the accountable Lead. The
signed handoff stores only its SHA-256 digest and bounded routing metadata; it
does not retain raw prompt text, page content, source, provider output,
screenshots, logs, secrets, or hidden reasoning.

## Authority check

`jstack_dispatch_check(dispatch_phase="browser-remediation")` requires:

- a current dispatch-eligible signed Team Plan and exact coordination packet;
- task mode `implement` or `fix`;
- exactly one existing writer with non-empty bounded write scopes;
- one read-only `browser-qa-engineer` on another physical agent;
- a fresh, complete, untruncated `outcome=fail` browser receipt for the exact
  current Git HEAD, fingerprint, policy, build, runtime, and scenario;
- a finding bound to that receipt; and
- for fix-classified work, the existing Stage 9 passing root-cause receipt.

A passing, blocked, error, truncated, stale, altered, differently scoped, or
mutation-bearing QA result cannot unlock the Builder. Review, diagnosis, test,
plan, or audit task modes cannot be upgraded by browser evidence.

The returned `browser-remediation-handoff` receipt attests the original
candidate, evidence, finding digest, Team Plan digest, writer, write scopes,
independent QA assignment, and mandatory re-QA rule. It does not grant new
authority; it only preserves the authority already approved and composed.

## Candidate invalidation and re-QA

The Builder runs only the returned `jstack.dispatch-slice.v1`. Once source
changes, the old Team Plan and browser evidence cannot validate the new
fingerprint. Re-QA uses `jstack_browser_capture` with:

- fresh trusted revision/fingerprint/policy values from discovery;
- the exact handoff receipt;
- the same scenario digest;
- a changed project fingerprint;
- a changed build digest; and
- a closed candidate-bound provider result.

The fresh browser receipt records the handoff digest, finding digest,
superseded evidence digest, and `priorEvidenceStale=true`. A fresh pass sets
`findingResolved=true`; a fresh failure receives failing evidence and remains
open. Re-QA still runs repository-controlled code in a scrubbed but non-sandboxed
local process and needs separate trusted-execution approval.

## Upstream disposition

Pinned `qa/SKILL.md.tmpl`, `qa-only/SKILL.md.tmpl`, and
`browse/src/browser-skill-commands.ts` were researched. JStack preserves useful
finding and verification concepts while explicitly rejecting upstream-style
automatic fixes, commits, browser state, prompts, providers, installers, and
action authority. Provenance record
`gstack-browser-qa-remediation-adaptation` is an original JStack `ADAPTED`
Class A control.

## Compatibility, rollback, and advance gate

The public surface remains six commands, 60 canonical tools, and 52 frozen
aliases. Stage 12 adds optional fields and one enum value to the existing
dispatch successor contract, plus one optional field on the Stage 11 canonical
tool. Frozen alpha.9 shapes normalize through the compatibility checker.

Rollback removes the finding module/schema, browser-remediation dispatch phase,
handoff receipt, and re-QA binding. Stage 11 browser evidence and all earlier
JStack workflows continue unchanged.

The stage passes only if tests demonstrate that QA cannot write, a non-mutating
task cannot escalate, only the original independent Builder slice is returned,
passing/stale/altered findings are rejected, the old evidence becomes stale
after the change, re-QA requires the same scenario and new build, and only fresh
passing evidence resolves the finding. No result authorizes commit, push,
release, deployment, installation, or production mutation.

The Stage 12 focused gate passed 63 tests with three declared optional-schema
skips. Contract compatibility, canonical/generated sync, immutable
761-file/12-record provenance, Python compilation, six-command/60-canonical/
52-frozen-alias product boundaries, and `git diff --check` also passed.
