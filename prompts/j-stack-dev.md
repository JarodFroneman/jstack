---
description: Run JStack enterprise workflow in single-lead mode
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `single-lead`.

This command uses the `j-stack-dev` operating topology: one accountable Lead
and normally one physical agent. Do not add optional staffing. A mandatory
risk-floor independence check returned by Team Composer may add one read-only
physical assurance agent; that safety escalation does not change the command,
task mode, write authority, or user scope. If optional breadth is requested,
direct the user to `/jstack-subagents` or `/jstack-full-team`.

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
   digest, or terminal paste. When context is ready, display the complete
   `renderedCodexPrompt` and wait for the user to approve it or request changes.
   Do not plan or execute yet. Changes to goal, task mode, authority,
   constraints, or non-goals restart Stage A; other changes require a new Stage
   B preview. Every revision invalidates the old preview. After explicit
   approval, repeat Stage B with the
   exact internal `promptPreviewReceipt` and approval bound to the displayed
   `renderedPromptSha256`. Never infer approval or ask the user to handle those
   values. Only the approved response's `compilationReceipt` and nested
   `readinessReceipt` may be used downstream. For `implement` or `fix`,
   repository inspection must also supply one source-labelled
   `authorized_write_scopes` fact whose value is a bounded
   repository-relative path or JSON string array. This constrains the eventual
   writer; it is not action approval. Never use the repository root, an
   invented placeholder, or unrelated dirty paths as scope.
6. For `git`, use `jstack_policy_check`,
   `jstack_plan(team_mode="single-lead", quality_level="enterprise",
   operating_profile=explicit_user_profile_or_professional,
   host_id=current_supported_host,
   learning_mode=resolved_learning_mode,
   context_readiness_receipt=stage_b.contextReadiness.readinessReceipt,
   context_brief=stage_b.contextReadiness.normalizedBrief)`,
   apply the returned Lead `capabilityIds`, and use `jstack_preflight` when
   applicable. Capability packs specialize the Lead but never expand
   permissions. Treat `agentTeam.unifiedTeamPlan` as the execution source only
   when `agentTeam.executionSource="team-composer"` and
   `agentTeam.dispatchEligible=true`. Its logical specialists, physical-agent
   allocation, scopes, independence boundaries, and evidence contracts are
   exact. If the plan is blocked or preview-only, stop and resolve its stated
   binding/scope issue; never fall back silently. The `agents` array is a
   temporary legacy compatibility view, not a dispatch roster. If an
   independent physical agent is required, pass the complete `agentTeam`
   object and exact `dynamicCoordinationPacket` to `jstack_dispatch_check`
   before dispatch.
   Read the receipt-bound `agentTeam.methodologyPlan` before execution. Apply
   only its selected JStack-native methodology records, phases, output
   contract, evidence requirements, and stop conditions; an empty selection is
   valid. Never invoke an upstream gstack skill or giant prompt directly.
   Methodology selection adds required expertise and evidence but cannot alter
   the approved task mode, scope, permissions, provider access, persistence,
   implementation authority, or external-action authority.
   Also consume the receipt-bound `hostContract`,
   `professionalDeliveryPipeline`, and `securityProviderPlan`. Use only
   `AVAILABLE` host capabilities, follow only required delivery phases, and
   disclose security gaps. Profile, host, or evidence state never grants
   action authority.
   When `root-cause-investigation` is selected, call
   `jstack_dispatch_check` even if every logical specialty maps to the Lead.
   For `fix` or an investigation-selected `implement`, first use
   `dispatch_phase="investigation"` and execute only its read-only
   `executionSlice`; do not edit source. The exact root-cause assignment must
   return `jstack.investigation.v1` through `jstack_specialist_result`. Three
   consecutive falsified or inconclusive hypotheses require a later revised
   trace, changed hypotheses, `status="unresolved"`, and an immediate stop;
   never try a fourth random patch. Remediation may begin only after
   `jstack_dispatch_check(dispatch_phase="remediation",
   investigation_receipt=...)` accepts that unchanged-candidate specialist
   receipt. Execute only its remediation slice under the original writer
   scope. `diagnose-only`, an unresolved cause, and evidence/readiness never
   authorize a fix.
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
11. In Git mode, submit one exact `jstack.specialist.result.v1` and
   metadata-only `jstack.specialist.telemetry.v1` for every
   `dynamicReceiptAssignments` entry. Pass the exact
   `unifiedTeamPlanReceipt`, `specialistId`, `physicalAgentId`, canonical
   `roleId`, capability IDs, and write scope to `jstack_specialist_result`.
   The exact `root-cause-investigator` call must also include the in-memory
   `investigation_contract`; only its digest-only certification may enter the
   receipt.
   Then call `jstack_specialist_handoff_check` with the same Team Plan receipt
   and the ordered role/capability projection of those assignments. Never
   store raw prompts, messages, tool arguments, command/model output, source
   contents, or secrets. A missing, failed, partial, stale, scope-drifted, or
   capability-incomplete logical-specialist receipt blocks completion.
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

If the task needs optional breadth beyond the Team Composer's mandatory Dev
risk floor, stop and recommend `/jstack-subagents` or `/jstack-full-team`
rather than silently widening the operating topology.

Use the installed `jstack-dev` skill and normal Codex fallback only when
`jstack_runtime_status` itself is unavailable or unreachable. Never relabel a
Git requirement, invalid input, policy denial, or failed gate as an MCP
attachment failure. Upstream gstack is optional.
