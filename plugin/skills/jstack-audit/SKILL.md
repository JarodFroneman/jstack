---
name: jstack-audit
description: Run evidence-bound, read-only JStack code audits across correctness, security, architecture, maintainability, performance, supply chain, tests, data integrity, compatibility, and operations. Use when the user invokes the jstack-audit skill or command, requests a repository audit or release go/no-go review, asks to challenge existing findings, or wants the JStack audit mastery track.
---

# JStack Audit

When an active JStack loop requests audit evidence, remain read-only and return
only the audit result and receipt. Never adopt the loop's editing role or
declare the native goal complete.

Audit the declared subject without changing application code, configuration,
Git state, installed tools, or production. Treat the MCP as a deterministic
evidence and validation layer; semantic code review remains the Audit Lead's
reasoned work.

## Start

1. Parse `[SCOPE]` and the options `--profile`, `--focus`, `--base`,
   `--fail-on`, `--format`, `--verify`, `--learning-mode`, and `--team-mode`.
2. Return usage only for `help`, `--help`, or `?`; do not inspect a repository.
3. Read project instructions and relevant durable context.
4. Call `jstack_runtime_status`, then `jstack_detect_project`.
5. Call `jstack_audit` to bind the subject, controls, profile, scope manifest,
   adapter inventory, review evidence, existing secret-scan evidence, and the
   focus-routed `specialistCapabilityPlan`. Its capability audit domains may
   strengthen required coverage but may never remove profile or policy domains.
6. Generate candidate findings from cited source evidence, then run a separate
   challenge pass that looks for guards, callers, tests, reachability limits,
   and mitigating controls.
7. Call `jstack_audit_finalize` with the coverage manifest, surviving findings,
   accepted-risk records, and requested formats.
8. Report the result, coverage, findings, blockers, residual risk, and next
   action. Never translate `incomplete` or `error` into a clean result.

Use [audit-methodology.md](references/audit-methodology.md) for profiles,
coverage, evidence collection, team waves, and report structure. Use
[finding-contract.md](references/finding-contract.md) while creating or
challenging findings. Read [audit-mastery.md](references/audit-mastery.md) only
when learning or assessment is requested.

## Project Modes

For `git`, require an exact repository root, HEAD, base commit when supplied,
workspace fingerprint, policy digest, control digest, scope-manifest digest,
adapter inventory, and active MCP session. Any relevant state change makes the
session stale.

For `artifact-only`, return the aggregate scope-manifest digest and explicit limitations. Do not
issue a Git-bound audit receipt, call the result release certification, or
report formal release readiness.

## Launch-Assurance Relationship

For a release-profile audit, identify observable product surfaces and launch
risks, but never silently declare the accountable launch profile. When the
surrounding task supplies a current `jstack_launch_assess` selection, map cited
audit evidence and findings to its applicable controls and keep uncovered
controls explicit. Register a launch-control artifact only when the Audit Lead
actually verified that bounded claim and can be named as its verifier.

An audit receipt and a launch receipt are separate evidence layers. Neither
substitutes for the other. Production profiles containing `public-web`,
`commercial`, `payments`, or `regulated-data` require a complete repository-wide
release-profile audit by default before release readiness. Legal, merchant-of-
record, consent, live-payment, mailbox, DNS, device, and provider facts remain
human or external evidence; source review must not invent them.

## Finding Standard

- Separate severity, confidence, and organisational priority.
- Cite a repository-relative path and exact source range.
- Classify evidence as `test-reproduced`, `tool-confirmed`, `source-proven`,
  `reasoned-strong-evidence`, or `unverified-hypothesis`.
- Do not let an unverified hypothesis block a release.
- Do not call a security weakness exploitable without a reachable path,
  preconditions, affected asset, and mitigating-control review.
- Do not claim a performance gain without a retained reproducible benchmark.
- Do not report style preferences as maintainability defects.
- Never include raw secret values, credentials, private keys, or sensitive
  source previews.

## Safety

- Keep the audit read-only. Remediation belongs in a separate development task.
- Never call the external-action challenge, authorize, or consume tools. An
  audit request, audit result, release-profile pass, or remediation plan grants
  no authority to create a repository, change a remote, commit, push, open a
  pull request, merge, tag, release, deploy, or mutate production.
- Do not run repository-controlled code by default.
- Never run repository-controlled code under the Quick profile.
- Run only a curated adapter after exact execution approval is bound to the
  current revision, workspace fingerprint, policy digest, and adapter command.
- Do not accept caller-defined executable paths, commands, shell strings, or
  network-enabled adapters.
- Treat offline adapter flags as requests, not network isolation. Approved
  adapters still require trusted code or an externally enforced container/VM.
- Stop on scope escape, symlink traversal, file identity change, size/time/output
  caps, stale evidence, missing mandatory coverage, or malformed suppression.
- Preserve `jstack_security_audit` as a separate bounded secret scanner and
  preserve its existing receipt semantics.

## Team Modes

Default to one Audit Lead. `smart-subagents` may use up to three relevant
read-only specialists with a validated coordination packet. `full-team` uses
controlled discovery, domain review, verification, and synthesis waves. No
specialist edits audited code. The Audit Lead owns the final evidence decision.

Capability packs specialize the existing audit roles; they do not create a new
command or grant tools, writes, delegation, approval, or release authority.
Use the exact catalog and selection digests returned by `jstack_audit`. If a
specialist team is deployed, first obtain the matching `jstack_team_plan`, give
each read-only role only its routed capability subset, and require structured
specialist results plus privacy-safe telemetry. Validate them through
`jstack_specialist_result` and `jstack_specialist_handoff_check` before Audit
Lead synthesis. Never store raw prompts, messages, tool arguments, command or
model output, source contents, credentials, or secrets in telemetry.

The final audit receipt binds the capability catalog, selection, and selected
IDs alongside the existing subject, controls, coverage, and finding digests.
This binding proves contract consistency, not semantic finding truth.

## Result Semantics

- `pass`: required coverage is complete and no verified unsuppressed finding
  meets the failure threshold.
- `fail`: coverage is complete and at least one verified unsuppressed blocker
  meets the threshold.
- `incomplete`: required evidence, files, tools, adapters, tests, or coverage
  are missing, capped, stale, or inconclusive.
- `error`: invalid input or a protocol/system failure prevented completion.

Only `pass` sets `passed=true`.
