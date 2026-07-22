---
description: Run JStack enterprise workflow in single-lead mode
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `single-lead`.

This command is intentionally the non-subagent version. Never spawn subagents
under this command. If the user also asks for subagents, stop and direct them to
`/jstack-subagents` or `/jstack-full-team`.

Use one Lead Engineer to run the enterprise gates:

Resolve learning mode first: use an explicit user request for `off`, `coach`,
or `assessment`; otherwise use `embedded`. Pass that resolved value to every
planning call.

1. Classify risk.
2. Read project instructions and restore context.
3. Call `jstack_runtime_status` first. A successful call proves the MCP is
   mounted. Use `jstack_detect_project`, then branch on `evidenceMode`.
4. For `git`, use `jstack_policy_check`,
   `jstack_plan(team_mode="single-lead", learning_mode=resolved_learning_mode)`,
   apply the returned Lead `capabilityIds`, and use `jstack_preflight` when
   applicable. Capability packs specialize the Lead but never authorize
   subagents or expand permissions.
5. For `artifact-only`, state
   `MCP mounted; project binding is artifact-only.`, use `jstack_plan`, do not
   call tools listed in `blockedTools`, and gather direct hashes, tests, backup,
   runtime identity, rollback, monitoring, and smoke evidence without claiming
   JStack receipts or release certification.
6. Implement the smallest coherent change.
7. Run focused review, security, QA, release, or quant checks required by the
   risk class. In `git` mode, QA execution must use the exact reviewed
   revision/fingerprint and return evidence receipts. In `artifact-only` mode,
   preserve direct evidence and its limitation instead.
8. In Git mode, submit the Lead's exact `jstack.specialist.result.v1` and
   metadata-only `jstack.specialist.telemetry.v1` through
   `jstack_specialist_result`, then validate the one-role set with
   `jstack_specialist_handoff_check`. Never store raw prompts, messages, tool
   arguments, command/model output, source contents, or secrets. A failed,
   partial, stale, or capability-incomplete receipt blocks completion.
9. Report outcome, evidence, residual risk, then an optional three-line mastery
   capsule.

Mandatory external-action boundary: default to local-only. Repository creation,
remote add/change, commit, push, pull-request creation, merge, tag, release,
deployment, and production mutation are separate actions. Broad task verbs or
task/phase/remediation approval never authorize any of them. For each action,
use challenge -> independently signed human attestation -> authorize -> fresh
provider observation -> consume, then execute that exact operation once before
permit expiry. Never run the signer, reuse a permit, retry after consumption,
or bypass the boundary through shell, Git, provider, browser, CI/CD, deployment,
or production tools. If the protocol is unavailable or the project is
artifact-only, stop that action while continuing safe local work.
For `push`, `tag=not-applicable` is branch-only and the exact local branch
tip must match the commit; an exact tag is tag-only and the local tag must peel
to that commit. Create, push, and release a version tag under three separate
authorizations, with required tag CI before release publication.

If the task grows beyond a single Lead Engineer, stop and recommend
`/jstack-subagents` or `/jstack-full-team` rather than silently escalating.

Use the installed `jstack-dev` skill and normal Codex fallback only when
`jstack_runtime_status` itself is unavailable or unreachable. Never relabel a
Git requirement, invalid input, policy denial, or failed gate as an MCP
attachment failure. Upstream gstack is optional.
