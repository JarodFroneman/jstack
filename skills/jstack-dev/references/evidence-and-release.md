# Evidence And Release

## Evidence Subject

QA and security receipts are signed by the active local MCP process and bound
to repository root, git HEAD, full project fingerprint, check identity, result,
and issue time. They expire after 24 hours and after any relevant project-state
change or MCP restart.

The signature protects against accidental or caller-side alteration. It does
not protect against compromise of the same operating-system account.

## Project Binding

Call `jstack_runtime_status` first. A successful response proves the MCP is
mounted independently of project eligibility. `jstack_detect_project` then
returns one of two evidence modes:

- `git`: commit-bound policy, QA, security, context, mastery, quant, and release
  tools are available.
- `artifact-only`: detection and planning are available, but every Git-bound
  tool remains blocked.

Artifact-only work must preserve direct SHA-256 mappings, exact test/build
records, a verified pre-change backup, immutable runtime identity, staged
dependency order, approval, rollback, monitoring, and internal/public smoke
checks. This evidence can support an explicitly approved operational decision;
it is not a JStack receipt or release-readiness result.

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
- explicit release request and approver reference for production
- rollback plan
- monitoring or canary plan

Missing, malformed, stale, failed, blocked, skipped, timed-out, truncated, or
inconclusive evidence is not a pass.

## Scanner Boundary

The local scanner reads bounded regular text files without following symlinks
and never returns matching source-line previews. Symlinks, unreadable files,
oversize text files, file-count limits, and finding-count limits make the scan
incomplete and therefore non-releasable.

It is a secret-pattern check, not a complete security program. Add dependency,
SAST, container, IaC, dynamic, and human review according to the changed
surface.
