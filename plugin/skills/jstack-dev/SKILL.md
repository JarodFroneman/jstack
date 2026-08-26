---
name: jstack-dev
description: Evidence-driven enterprise engineering and mastery workflow for JStack projects. Use when the user invokes /j-stack-dev, /jstack-subagents, or /jstack-full-team, or asks for JStack planning, implementation, review, QA, security, release readiness, project handoff, or deliberate engineering training.
metadata:
  short-description: Run JStack enterprise delivery and mastery
---

# JStack

JStack is an execution standard, not a claim that AI output is automatically
production-grade. Produce the smallest coherent change, gather independent
evidence, expose residual risk, and deny readiness whenever required evidence is
missing, stale, incomplete, or failed.

## Command Authority

The invoked command is the sole staffing authority:

- `/j-stack-dev`: `single-lead`. Use one physical Lead by default. Team
  Composer may add one read-only physical assurance agent only when a mandatory
  risk floor requires independence; optional breadth requires another command.
- `/jstack-subagents`: `smart-subagents`. The user explicitly approved a
  right-sized team, normally two or three physical specialist agents.
- `/jstack-full-team`: `full-team`. Represent every materially required
  engineering function and independence boundary using a dynamic specialist
  and physical-agent plan; never equate Full Team with a fixed roster.
- `/jstack-loop`: use the `jstack-loop` skill. The loop owns persistence and
  convergence while one explicitly selected delivery mode owns each iteration.
- `jstack-audit`: a separate read-only audit workflow. Use the
  `jstack-audit` skill; do not edit audited code or reinterpret the command as
  an implementation request.

Do not silently reinterpret one command as another. Staffing changes
coordination coverage, never the quality bar.

The JStack MCP plans, validates, scans, records, and evaluates evidence. It does
not spawn platform subagents. Use the platform multi-agent tools for real
dispatch, waiting, collection, and closure.

When an active loop supplies a `loopId`, execute only the current iteration in
the contract's fixed delivery mode. Let `jstack_loop_checkpoint` and
`jstack_loop_finalize` own convergence and terminal status.

## Start

1. Before repository inspection, durable-memory reads, planning, or any
   side-effecting tool, call
   `jstack_prompt_compile(stage="intent", workflow_mode=exact_command_mode,
   raw_request=exact_user_request)`. Preserve its exact `intentContract` and
   `intentReceipt`. It classifies intent and authority only; it authorizes no
   read, write, Git, external, release, deployment, or production action.
   Read [prompt-compiler.md](references/prompt-compiler.md) for the contract and
   disabled/shadow/preview/enforced modes.
2. Read repository instructions and relevant durable memory.
3. Call `jstack_runtime_status`. A successful response proves the MCP is
   mounted. Never describe a later project, input, policy, or gate rejection as
   an MCP attachment failure.
4. Use `jstack_detect_project` and inspect `evidenceMode`.
5. For `git`, inspect status, branch, project boundaries, stack, and checks,
   then use `jstack_policy_check` with the task goal and comparison `base_ref`
   when known.
6. Complete Prompt Compiler Stage B before planning. After inspecting all
   repository-answerable context, call
   `jstack_prompt_compile(stage="grounded", workflow_mode=exact_command_mode,
   intent_receipt=stage_a_receipt, intent_contract=stage_a_contract)` with
   source-labelled grounding, disclosed assumptions, requirements, acceptance
   and verification evidence, and only material open questions. Stage B
   extends the Adaptive Context Gate; do not call a duplicate
   `jstack_context_readiness` round. Ask questions returned under
   `contextReadiness` in normal chat,
   never more than three per round, each with its reason and recommended
   default. Clear prompts continue with zero questions. High-risk material defaults require explicit
   in-conversation confirmation; no token, digest, signer, or terminal paste is
   allowed. A confirmation call confirms only assumptions already shown: carry
   those assumptions forward, set `use_recommended_defaults=false`, and never
   apply a new default batch in the same call. Reuse answered facts and never
   repeat an unchanged question. Once context is ready, display the complete
   `renderedCodexPrompt` in normal chat and ask the user to approve it or request
   changes. Stop before planning, edits, dispatch, or other execution. Never
   infer approval from silence, a prior implementation request, a default, or a
   receipt. If requested changes alter the goal, task mode, authority,
   constraints, or non-goals, restart at Stage A with the revised request;
   otherwise add them as source-labelled user input and rerun Stage B. Display
   the complete revised prompt; the prior preview is invalid. After explicit
   approval, repeat Stage B with the exact
   internal `promptPreviewReceipt` and `prompt_approval` bound to the displayed
   `renderedPromptSha256`. Users never copy or paste those values. Only the
   approved response may return `compilationReceipt` and the nested
   `readinessReceipt`; pass that receipt and its matching `normalizedBrief` to
   planning as `context_readiness_receipt` and `context_brief`. A readiness or
   compilation receipt remains evidence, not authority. For `implement` or
   `fix`, include one source-labelled `authorized_write_scopes` fact containing
   a bounded repository-relative path or JSON string array derived from
   inspection. It constrains the one primary writer and authorizes nothing.
7. For `artifact-only`, state
   `MCP mounted; project binding is artifact-only.`, identify the authoritative
   source and deployment boundary, and do not call tools listed in
   `blockedTools`. Capture direct hashes, test output, backup, immutable runtime
   identity, rollback, monitoring, and public smoke evidence without claiming
   commit-bound JStack receipts or release certification.
8. Use `jstack_plan` with the exact command `team_mode`,
   `quality_level="enterprise"`, the explicit governance
   `operating_profile` (default `professional` when the user did not choose),
   the actual current `host_id`, requested `learning_mode`, and the current
   `context_readiness_receipt` plus matching `context_brief`. When
   `agentTeam.executionSource="team-composer"` and `dispatchEligible=true`,
   consume the signed `unifiedTeamPlan`; its logical specialists, physical
   allocation, scopes, independence boundaries, and evidence contracts are the
   execution source. The legacy `agents`/`capabilityPlan` view is not the active
   roster. Stop on blocked, shadow, or preview-only state instead of falling
   back silently. Read its receipt-bound `methodologyPlan` and apply only the
   selected JStack-native methodology records. An empty selection is valid.
   Methodology phases, output contracts, evidence, and stop conditions inherit
   the approved task mode and canonical-role ceiling; they grant no write,
   provider, persistence, external-action, release, or deployment authority.
   Treat the returned `hostContract`, `professionalDeliveryPipeline`, and
   `securityProviderPlan` as closed, receipt-bound evidence contracts. Use only
   host capabilities marked `AVAILABLE`; follow only required delivery phases;
   and disclose security gaps instead of silently substituting weaker checks.
9. For specialist modes, use `jstack_team_plan` with the same readiness receipt
   and normalized brief,
   pass the complete returned `team` and its exact
   `dynamicCoordinationPacket` to `jstack_dispatch_check`. Dispatch only the
   physical agents and logical assignments in the signed Team Plan.
   When the signed `methodologyPlan` selects `root-cause-investigation`, call
   the dispatch gate even in single-lead mode. For `fix` or an
   investigation-selected `implement`, run only
   `dispatch_phase="investigation"` first, submit the exact
   `jstack.investigation.v1` result through the read-only root-cause
   assignment, and call `dispatch_phase="remediation"` with its passing
   unchanged-candidate receipt before any source edit. Run only the returned
   phase `executionSlice`. Diagnosis-only or unresolved evidence never unlocks
   remediation.
10. In `git` mode, use `jstack_preflight` before substantial implementation and
   before handoff.

Use the normal-Codex fallback only when `jstack_runtime_status` itself is
unavailable or unreachable. Upstream gstack is optional; JStack is
independently usable.

## Delivery Gates

### Context

- Read `AGENTS.md`, README, architecture, security, contribution, and relevant
  project docs before editing.
- Restore saved context when resuming.
- Load only task-relevant durable memory.
- Distinguish source truth, generated artifacts, and installed copies.
- Keep user, repository, policy, external-evidence, and inferred facts
  distinguishable. Disclose assumptions and their effect on the plan.
- Ask only material questions after inspection, at most three per round, and
  include a recommended default. Never turn this into terminal approval work.

### Plan

- Classify all matching domains: normal, architecture, product/UI,
  security/compliance, data/financial, and production/release.
- Use the strictest combined gates.
- State acceptance criteria, invariants, failure modes, test evidence, and
  rollback or compatibility needs before broad work.
- Keep one lead accountable for synthesis and final decisions.

### Build

- Follow local architecture and conventions.
- Make the smallest coherent diff.
- Do not invent APIs, data, file contents, test results, or operational state.
- Avoid unrelated refactors, dependency churn, and generated-file drift.
- Add tests proportional to risk and blast radius.

### Review

- Review the complete release delta: committed `base..HEAD`, staged, unstaged,
  and untracked changes.
- Lead findings with correctness, security, data loss, compatibility,
  production risk, and missing tests.
- Treat policy files, workflows, secrets, production config, infra, and
  migrations as protected surfaces.
- Use `jstack_review` and specialist review where the command permits it.

### QA

- `jstack_qa` discovery is read-only; discovered commands are repository code,
  not trusted JStack code.
- Before execution, inspect the command and exact project fingerprint. Set
  `execution_approved=true` only when local project checks are authorized and
  the reviewed revision/fingerprint match.
- Run all checks relevant to the changed surface. Record command, exit status,
  and receipt. A discovered, skipped, blocked, timed-out, or failed command is
  not a pass.
- Browser/UI work also needs runtime interaction and responsive visual evidence.
- For an authorized browser/UI check, read
  [browser-provider.md](references/browser-provider.md), discover first with
  `jstack_browser_capture(run=false)`, inspect the exact project script and
  candidate binding, then execute only after separately approving that trusted
  local command. A browser receipt is evidence only and never permits QA to
  edit source or perform Git, release, deployment, production, or external
  actions.
- In `artifact-only` mode, run authorized checks directly and preserve the same
  evidence fields, but label them direct evidence rather than JStack receipts.

### Security

- Use `jstack_security_audit` for substantial and sensitive work.
- Apply the receipt-bound `securityProviderPlan`. High and production risk
  require independent scanner evidence; a JStack self-check cannot substitute
  for an unavailable independent provider.
- Scan incompleteness, file/symlink errors, findings, auth gaps, secret
  exposure, unsafe public output, and unreviewed trust boundaries are blockers.
- A clean heuristic secret scan does not replace dependency, SAST, container,
  infrastructure, or human security review when those are relevant.

### Launch Assurance

- For a clean committed production candidate, declare `core` plus every real
  product surface, the risk tier, and an immutable deployment fingerprint, then
  call `jstack_launch_assess`. Reconcile every detected-but-omitted surface with
  an accountable evidence reference; never omit a surface to avoid a control.
- Register every active evidence requirement with
  `jstack_launch_evidence_register` using native structured JSON,
  provider-neutral scanner JSON, or SARIF as permitted by the assessment.
  Never supply or infer a prose `pass`; JStack derives the outcome from exact
  assertions, completeness, observations, producer, target, and independence.
- Call `jstack_launch_finalize`. Missing, stale, failed, incomplete, duplicate,
  contradictory, truncated, or drifted blocker/required evidence prevents
  readiness. High-risk security requires an independent scanner; critical risk
  also requires an independent human security review and permits no waiver.
- Keep launch checks conditional. Email, search, browser, analytics, payment,
  tracking, legal, and regulated-data controls activate only for declared
  surfaces. Preserve existing accessibility, supply-chain, migration, backup,
  data-integrity, compatibility, and incident-recovery gates.

### Release

- JStack adds no custom approval challenge, token, signer, mailbox, or terminal
  approval step. Never ask the user to run or paste one.
- Perform repository, Git, provider, deployment, and production actions only
  when they are within the user's explicit request, the active task scope, and
  normal Codex/provider permissions. Follow the host's ordinary approval UI
  when it appears.
- Resolve exact targets before irreversible operations, re-check current state,
  and do not infer authority for a materially different repository, branch,
  tag, environment, or action.
- Keep action execution separate from readiness evidence. A passing audit,
  launch receipt, release-readiness result, phase gate, or completion receipt
  does not itself run an operation.
- Use `jstack_ship_check` and `jstack_release_readiness` with current QA,
  security, and production launch-assurance receipts. Public-web, commercial,
  payment, and regulated-data profiles also require a release-profile audit by
  default.
- Pass the intended `release_strategy` (`direct`, `canary`, or `blue-green`)
  and present the returned `releaseChoreography`. Its
  `executionAuthorized=false` state is permanent; a passing choreography only
  identifies the next separately authorized host/provider action.
- Readiness requires a clean committed subject, every discovered required
  command passing for that exact fingerprint, complete security evidence,
  applicable structured launch evidence, approver reference, rollback plan, and
  monitoring or canary plan.
- Release readiness is evidence only and `executionAuthorized` remains false.
  Never equate implementation completion or readiness with deployment
  completion.
- `artifact-only` work may prepare direct operational evidence, but JStack
  release readiness remains unavailable until the authoritative source has a
  committed Git repository.

### Handoff

- State outcome, files changed, exact checks and results, residual risk, and
  open work.
- In Git mode, create a `jstack.specialist.result.v1` result and
  `jstack.specialist.telemetry.v1` metadata envelope for every exact
  `dynamicReceiptAssignments` entry. Call `jstack_specialist_result` with the
  signed Team Plan receipt, specialist ID, physical-agent ID, canonical role,
  capability IDs, and write scope. For the exact
  `root-cause-investigator`, also pass its in-memory
  `investigation_contract`; the receipt may retain only its digest-only
  certification. Then call
  `jstack_specialist_handoff_check` with the same Team Plan receipt and the
  ordered role/capability projection before the final completion claim.
- Telemetry contains identifiers, timestamps, status, tool names/statuses,
  evidence references, and optional counts only. Never store raw prompts,
  messages, tool arguments, command output, model output, secrets, or source
  contents. Let the MCP derive input and output digests.
- A structurally valid partial or blocked receipt is evidence of the stop, not
  a pass. Missing logical specialists, stale/tampered receipts, physical-agent
  or capability drift, overlapping change ownership, unresolved
  contradictions, or an open Lead resolution block handoff.
- Use `jstack_context_save` for resumable substantial work.
- Update durable memory only for durable facts or decisions.
- Never call work production-ready when a required gate is absent.

## Specialist Modes

Before dispatch, require the exact `jstack.team-coordination.v2` packet
returned with the signed Team Plan. It binds the Team Plan digest, requested
task mode, physical agents, logical specialists, canonical roles, file owner,
evidence contracts, stop conditions, and handoff rule. A regenerated, edited,
boolean, or legacy packet cannot validate dynamic dispatch.

Exactly one Team Plan assignment may write, and only inside the source-labelled
bounded scope. All other logical specialists are read-only. Unknown
specialists, traversal, root ambiguity, assignment drift, independence
collapse, or overlapping ownership block dispatch.

Capability packs add methods, required evidence, stop conditions, audit
domains, and loop controls to an existing role. They never add tools, write
permission, scope, delegation authority, approval authority, or release
authority. Give each specialist only its routed capability subset. Require the
specialist to return the structured result fields, privacy-safe telemetry, and
all capability-required evidence kinds. The Lead issues/validates receipts and
records an explicit evidence-backed resolution for contradictory findings.

The separate methodology-capability catalog contains the seven Stage 8
product-discovery, product-review, plan-review, investigation, and
retrospective methods. Use the exact `methodologyPlan` returned with the Team
Plan; do not invoke upstream gstack skills or large prompt templates directly,
and do not invent a methodology when selection is empty. The signed Team Plan
receipt binds the current methodology catalog and selection digests.

Root-Cause Investigation is a Stage 9 execution gate, not merely advice.
Every `fix` selects it. The investigation phase is read-only and follows
problem, observed behavior, reproduction, execution trace, unique falsifiable
hypothesis, falsification attempt, and conclusion. After three consecutive
falsified or inconclusive hypotheses, add a later trace revision bound to the
three attempts, keep the cause explicitly unresolved, and stop; a fourth
random patch is rejected. Remediation requires the exact passing
investigation specialist receipt, unchanged Git candidate, mutating approved
task mode, and original scoped writer. The receipt grants no authority.

For `/j-stack-dev`, Team Composer normally maps every required capability to
one Lead physical agent. It may map a mandatory independent assurance function
to one separate read-only agent; never treat this safety floor as optional
staffing or expanded action authority.

For full-team work, wave only the selected Team Plan:

1. Discovery: selected read-only architecture, product, investigation, and
   domain specialists.
2. Build: the single scoped Team Plan writer.
3. Review: selected independent QA, review, security, browser, reliability, or
   release assurance.
4. Synthesis: Lead reconciles evidence and makes the bounded go/no-go call.

Read [team-coordination.md](references/team-coordination.md) when using either
specialist command. Read
[delivery-profiles-and-hosts.md](references/delivery-profiles-and-hosts.md)
whenever consuming a Unified Team Plan, security-provider plan, host contract,
delivery pipeline, or release choreography. Read
[methodology-capabilities.md](references/methodology-capabilities.md) whenever
the returned methodology selection is non-empty. Read
[root-cause-investigation.md](references/root-cause-investigation.md) whenever
that exact method is selected.

## Mastery

Learning modes:

- `off`: enterprise execution without visible instruction.
- `embedded` (default): finish with at most one mental model, one decision
  checkpoint, and one next drill in three lines.
- `coach`: explain decisions interactively while preserving delivery pace.
- `assessment`: do not reveal hidden answers before the attempt; score submitted
  evidence only.

Use `jstack_mastery_start`, `jstack_mastery_status`, and
`jstack_mastery_record`. The optional `track` is `engineering` by default;
`jstack-audit` uses `track="audit"`. Learner stage is demonstrated ability;
task domain is the risk of the current work. Never promote a learner because a
task contains an advanced keyword.

When task risk exceeds learner stage, keep delivery under the full expert gate
while isolating assessment to the learner's current drill. For Stage 0, complete
the read-only orientation and required `.jstack-training/` artifacts before
implementation, or use a separate clean worktree. Do not award advanced-task
credit for work performed by the Lead or AI.

Normal output order is outcome, evidence, residual risk, then the optional
mastery capsule. Read [mastery-system.md](references/mastery-system.md) for the
curriculum, artifacts, scoring, advancement, and capstones.

## Anti-Slop Rule

JStack improves the process that produces code. It does not transform weak code
by declaration. Enterprise quality exists only when the implementation,
verification, security review, operational controls, and human judgment support
the claim.

Read [evidence-and-release.md](references/evidence-and-release.md) before
changing policy, QA execution, evidence receipts, installers, or release gates.
Read [launch-assurance.md](references/launch-assurance.md) before declaring a
production surface profile, registering launch evidence, or finalizing release
readiness.
Read [adaptive-context-gate.md](references/adaptive-context-gate.md) before
changing intake, clarification, assumptions, planning receipts, or any of the
five command entry workflows.
