# Evidence And Release

## Evidence Subject

QA, security, audit, and launch receipts are signed by the active local MCP process and bound
to repository root, git HEAD, full project fingerprint, check identity, result,
and issue time. They expire after 24 hours and after any relevant project-state
change or MCP restart.

The signature protects against accidental or caller-side alteration. It does
not protect against compromise of the same operating-system account.

## Project Binding

Call `jstack_runtime_status` first. A successful response proves the MCP is
mounted independently of project eligibility. `jstack_detect_project` then
returns one of two evidence modes:

- `git`: commit-bound policy, QA, security, launch, context, mastery, quant, and
  release tools are available.
- `artifact-only`: detection and planning are available, but every Git-bound
  tool remains blocked.

Artifact-only work must preserve direct SHA-256 mappings, exact test/build
records, a verified pre-change backup, immutable runtime identity, staged
dependency order, approval, rollback, monitoring, and internal/public smoke
checks. This evidence can support operator review, but it is not a JStack
receipt, release-readiness result, or protected-action authorization.

## Project Commands

Test discovery reads package metadata and known language files. It does not make
those commands safe. Execution requires:

- explicit local execution approval
- exact reviewed git revision
- exact reviewed project fingerprint
- `shell=False`
- closed stdin
- scrubbed environment and isolated home
- bounded output and timeout with process-group termination

The current user's filesystem and network privileges still apply. Use a real
container/sandbox in projects that require stronger isolation.

If a check changes tracked or untracked project state, its pass receipt is
invalidated. Generated ignored files remain governed by project policy.

## Release Decision

Release readiness denies by default. It needs:

- a project policy
- a resolvable comparison base that is a distinct pre-release ancestor; HEAD
  cannot be its own baseline
- complete protected-path review over committed and worktree changes
- clean committed repository state
- one current passing receipt for every discovered required command
- complete current security receipt
- a current passing launch receipt for production, based on `core` plus every
  applicable product surface
- a current release-profile audit receipt when the launch profile includes a
  policy-triggering public, commercial, payment, or regulated-data surface
- explicit release request and approver reference for production
- rollback plan
- monitoring or canary plan

Missing, malformed, stale, failed, blocked, skipped, timed-out, truncated, or
inconclusive evidence is not a pass.

Readiness is evidence, not execution. Its result always reports
`executionAuthorized=false`.

Use [launch-assurance.md](launch-assurance.md) for profile declaration,
per-control evidence, not-applicable rules, waivers, freshness, and the
live-provider safety boundary.

## Host-Native Action Safety

JStack v0.8.2 has no approval challenge, token, signer, mailbox, or terminal
approval step. Repository, Git, provider, deployment, and production actions
use the user's explicit request and normal Codex/provider permissions.

The accountable Lead resolves exact targets, rechecks current state, follows
ordinary host approval UI when it appears, and does not infer authority for a
materially different action. Readiness results, audit results, human gates,
specialist handoffs, and loop/program receipts remain evidence; they do not
execute operations or widen task scope.

See [Host-Native Action Safety](../../../docs/action-safety.md).

## Scanner Boundary

The local scanner reads bounded regular text files without following symlinks
and never returns matching source-line previews. Symlinks, unreadable files,
oversize text files, file-count limits, and finding-count limits make the scan
incomplete and therefore non-releasable.

It is a secret-pattern check, not a complete security program. Add dependency,
SAST, container, IaC, dynamic, and human review according to the changed
surface.
