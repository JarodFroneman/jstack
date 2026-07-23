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

Readiness is evidence, not authority. Its result always reports
`executionAuthorized=false`.

Use [launch-assurance.md](launch-assurance.md) for profile declaration,
per-control evidence, not-applicable rules, waivers, freshness, and the
live-provider safety boundary.

## External-Action Authority

Every project defaults to local-only. Repository creation, remote add/change,
commit, push, pull-request creation, merge, tag creation, release creation,
deployment, and production mutation are separate actions. No goal word,
readiness result, audit result, phase approval, remediation approval,
specialist handoff, or loop/program receipt authorizes one.

Each action requires one `jstack_external_action_challenge` bound to the exact
provider, owner, repository, visibility, remote URL, branch, tag, full commit,
target environment, current Git/workspace/policy state, branch, remote snapshot,
tool version, and MCP session. A named role-holding human runs the returned
approval command outside Codex, reviews the exact fields, and confirms
`APPROVE ONCE`; JStack then collects the signed private response by
authorization ID. Codex must not run the command or ask for a pasted token.

For `push`, `tag=not-applicable` is a branch-only intent and the local branch
tip must equal `exactCommit`. An exact tag is a tag-only intent and that local
tag must peel to `exactCommit`. Do not push an annotated release tag under a
branch-push permit: create the local tag, push that tag, wait for required tag
CI, and create the release under three separate authorizations.

After `jstack_external_action_authorize`, independently observe the exact
provider target and call `jstack_external_action_consume`. The authorization is
destroyed on consumption and returns a maximum 60-second permit for one exact
operation. Failure, retry, drift, expiry, or another action requires a new
challenge. Never use shell, Git, provider, browser, CI/CD, deployment, or
production tooling to bypass this protocol.

See [the complete boundary](../../../docs/external-action-boundary.md).

## Scanner Boundary

The local scanner reads bounded regular text files without following symlinks
and never returns matching source-line previews. Symlinks, unreadable files,
oversize text files, file-count limits, and finding-count limits make the scan
incomplete and therefore non-releasable.

It is a secret-pattern check, not a complete security program. Add dependency,
SAST, container, IaC, dynamic, and human review according to the changed
surface.
