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

1. Before repository inspection, durable-memory reads, planning, or
   side-effecting tools, call
   `jstack_prompt_compile(stage="intent", workflow_mode="j-stack-dev",
   raw_request=$ARGUMENTS)`. Preserve the exact intent contract and receipt;
   they grant no execution authority.

Resolve learning mode next: use an explicit user request for `off`, `coach`,
or `assessment`; otherwise use `embedded`. Pass that resolved value to every
planning call.

2. Classify risk.
3. Read project instructions and restore context.
4. Call `jstack_runtime_status`. A successful call proves the MCP is
   mounted. Use `jstack_detect_project`, then branch on `evidenceMode`.
5. Inspect repository instructions, stack, relevant files, and durable context,
   then call `jstack_prompt_compile(stage="grounded",
   workflow_mode="j-stack-dev")` with the exact Stage A receipt and contract,
   source-labelled grounding, separate assumptions, and only material open
   questions. This extends the Adaptive Context Gate; do not run a duplicate
   `jstack_context_readiness` round. Ask at most the returned
   `contextReadiness.questions` in normal chat, explain
   why each matters, and include its recommended default. Clear prompts ask
   nothing. Reuse answers and never repeat unchanged questions. Low-risk
   defaults may proceed as disclosed assumptions; high-risk material defaults
   require explicit conversational confirmation. A confirmation call may
   confirm only assumptions already shown; it must not apply a new default
   batch in the same call. Never request a token, signer,
   digest, or terminal paste.
6. For `git`, use `jstack_policy_check`,
   `jstack_plan(team_mode="single-lead", learning_mode=resolved_learning_mode,
   context_readiness_receipt=stage_b.contextReadiness.readinessReceipt,
   context_brief=stage_b.contextReadiness.normalizedBrief)`,
   apply the returned Lead `capabilityIds`, and use `jstack_preflight` when
   applicable. Capability packs specialize the Lead but never authorize
   subagents or expand permissions.
7. For `artifact-only`, state
   `MCP mounted; project binding is artifact-only.`, use `jstack_plan` with the
   current readiness receipt and normalized brief, do not
   call tools listed in `blockedTools`, and gather direct hashes, tests, backup,
   runtime identity, rollback, monitoring, and smoke evidence without claiming
   JStack receipts or release certification.
8. Implement the smallest coherent change.
9. Run focused review, security, QA, release, or quant checks required by the
   risk class. In `git` mode, QA execution must use the exact reviewed
   revision/fingerprint and return evidence receipts. In `artifact-only` mode,
   preserve direct evidence and its limitation instead.
10. For production readiness in Git mode, declare `core` plus every applicable
   product surface, risk tier, and immutable deployment fingerprint with
   `jstack_launch_assess`; reconcile detected omissions, register every active
   structured requirement with `jstack_launch_evidence_register`, and require a
   passing `jstack_launch_finalize` receipt. JStack derives outcomes from
   assertions. High-risk security requires an independent scanner; critical
   risk also requires independent human security review and permits no waiver.
   Public-web, commercial, payment, and regulated-data profiles also require a
   release-profile audit by default. Launch readiness is evidence only.
11. In Git mode, submit the Lead's exact `jstack.specialist.result.v1` and
   metadata-only `jstack.specialist.telemetry.v1` through
   `jstack_specialist_result`, then validate the one-role set with
   `jstack_specialist_handoff_check`. Never store raw prompts, messages, tool
   arguments, command/model output, source contents, or secrets. A failed,
   partial, stale, or capability-incomplete receipt blocks completion.
12. Report outcome, evidence, residual risk, then an optional three-line mastery
   capsule.

Native action safety: JStack never generates approval challenges, tokens,
signing commands, or terminal approval steps. Repository, Git, provider,
deployment, and production actions may be performed directly only when they
are within the user's explicit request, the current task scope, and normal
Codex/provider permissions. Keep exact targets visible, re-check state before
irreversible work, follow the host's ordinary approval UI when it appears, and
never infer permission for a materially different action. Audit remains
read-only, and evidence/readiness results never execute actions by themselves.

If the task grows beyond a single Lead Engineer, stop and recommend
`/jstack-subagents` or `/jstack-full-team` rather than silently escalating.

Use the installed `jstack-dev` skill and normal Codex fallback only when
`jstack_runtime_status` itself is unavailable or unreachable. Never relabel a
Git requirement, invalid input, policy denial, or failed gate as an MCP
attachment failure. Upstream gstack is optional.
