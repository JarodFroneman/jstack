---
name: jstack-full-team
description: Dynamically composed JStack workflow with complete material engineering coverage. Use when the user invokes /jstack-full-team or explicitly asks to deploy the full JStack team.
metadata:
  short-description: Deploy complete risk-aware JStack coverage
---

# JStack Full Team

Treat this command as explicit user approval to deploy a dynamically composed
JStack team when multi-agent tools are available. This is staffing approval
only; it does not widen task or action authority.

Full Team means complete coverage of every material engineering function and
mandatory independence boundary, not a fixed employee roster or uncontrolled
concurrency. Keep one accountable Lead and let the signed Team Plan select the
logical specialists, canonical-role ceilings, physical-agent allocation, and
dependency-aware waves required by the inspected task and risk.

Before repository inspection, durable-memory reads, planning, or
side-effecting tools, call
`jstack_prompt_compile(stage="intent", workflow_mode="jstack-full-team",
raw_request=exact_user_request)`. Preserve the exact Stage A contract and
receipt; they grant no execution authority or additional staffing authority.

Operating rules:

1. The Lead Engineer owns final scope, synthesis, implementation decisions, verification, and handoff.
2. Logical specialists are read-only by default.
3. Exactly one Team Plan assignment may edit source, and only inside its exact
   bounded source-labelled scope.
4. Documentation editing is allowed only when it is in the selected writer's
   exact scope.
5. Compatible logical specialists may share one physical agent; mandatory
   assurance independence must remain physically separate.
6. Dispatch selected physical agents in dependency-aware waves when that is
   safer or clearer.
7. Before dispatch, require the exact signed `unifiedTeamPlan` and complete
   `jstack.team-coordination.v2` packet.
8. After the approved Prompt Compiler gate below, pass the complete returned
   `team` object and exact `dynamicCoordinationPacket`
   to `jstack_dispatch_check` and call
   `jstack_plan` with `team_mode="full-team"`, the current
   `context_readiness_receipt`, its matching `normalizedBrief` as
   `context_brief`, and
   the resolved learning mode: explicit `off`, `coach`, or `assessment`,
   otherwise `embedded`. Pass the same receipt and brief to `jstack_team_plan`.
   Proceed only when `executionSource="team-composer"` and
   `dispatchEligible=true`. A blocked, shadow, or preview-only plan stops;
   never fall back silently. The legacy `agents` array is not the active
   roster.
9. The MCP plans and validates; platform multi-agent tools perform actual
   dispatch, collection, and closure.
10. Call `jstack_runtime_status` before project tools. A successful call proves
   the MCP is mounted. Use `jstack_detect_project` and branch on
   `evidenceMode`. For `artifact-only`, state
   `MCP mounted; project binding is artifact-only.`, keep team planning and
   dispatch validation, do not call tools listed in `blockedTools`, and gather
   direct artifact evidence without claiming JStack receipts or release
   certification. Only use the MCP fallback when `jstack_runtime_status`
   itself is unavailable or unreachable; never relabel a Git requirement or
   failed gate as an MCP attachment failure.
11. Before team planning or dispatch, inspect repository-answerable context and
    call `jstack_prompt_compile(stage="grounded",
    workflow_mode="jstack-full-team")` with the exact Stage A contract and
    receipt, source-attributed facts, separate
    assumptions, and only material open questions. Ask at most the returned
    three questions in normal chat, each with its reason and recommended
    default. Clear prompts ask nothing. Reuse answers and never repeat unchanged
    questions. Low-risk defaults may proceed as disclosed assumptions;
    high-risk material defaults need explicit conversational confirmation.
    Confirm only already displayed assumptions and never apply a new default
    batch in the same call. Do not run a duplicate
    `jstack_context_readiness` round. No token, signer, digest, or terminal
    paste is part of this gate. When context is ready, display the complete
    `renderedCodexPrompt` and wait for explicit approval or requested changes.
    Stop before team planning or dispatch. Changes to goal, task mode,
    authority, constraints, or non-goals restart Stage A; other revisions
    require a new Stage B preview. After approval, repeat Stage B with the exact internal
    `promptPreviewReceipt` and approval bound to the displayed prompt digest.
    Never infer approval or ask the user to handle receipt values. Use only the
    approved response's receipts downstream. For `implement` or `fix`, include
    a source-labelled `authorized_write_scopes` context fact containing a
    bounded repository-relative path or JSON string array derived from
    inspection. It constrains one writer and grants no action authority.

Dynamic coordination contract:

- exact Team Plan receipt and immutable prompt, context, project, repository,
  policy, workflow, risk, and task-mode bindings;
- ordered logical-specialist assignments and canonical-role ceilings;
- physical-agent allocation and mandatory separation edges;
- exact per-assignment capabilities, read/write scopes, evidence, and stop
  conditions;
- conflict, verification, and handoff rules; and
- `authorityEffect: none`.

The legacy 11 canonical roles may remain visible as a temporary compatibility
projection for old callers. They are not the selected team, may not drive
dispatch, and may not be used to manufacture missing specialist evidence.

Read the receipt-bound `methodologyPlan` before dispatch. Apply only selected
JStack-native methodology records and route their phases, output contracts,
evidence, and stop conditions to the mapped logical specialists. An empty
selection is valid. Never invoke upstream gstack skills or prompt templates
directly. Methodologies inherit the approved task mode, scope, canonical-role
permissions, and provider controls and add no persistence or action authority.

When `root-cause-investigation` is selected, it is a hard dependency before
the Build wave. For `fix` or an investigation-selected `implement`, first call
`jstack_dispatch_check(dispatch_phase="investigation")` and dispatch only its
read-only `executionSlice`; no writer may run or edit source. The investigator
submits `jstack.investigation.v1` through `jstack_specialist_result`. Three
consecutive falsified or inconclusive hypotheses require a later revised
execution trace, genuinely changed hypotheses, explicit unresolved state, and
a stop; never schedule a fourth random patch or hypothesis. Only an
established cause on the unchanged candidate may be passed to
`jstack_dispatch_check(dispatch_phase="remediation",
investigation_receipt=...)`; dispatch only the returned remediation slice
under the original Team Plan scope. Diagnosis-only or unresolved work cannot
enter the Build wave.

Full-team wave pattern:

1. Discovery: selected read-only architecture, product, domain, and
   investigation specialists produce bounded evidence.
2. Build: the single selected writer acts only inside its exact scope.
3. Review: selected independent review, QA, security, browser, reliability,
   accessibility, performance, or release specialists inspect the candidate.
4. Synthesis: Lead reconciles evidence, resolves conflicts, verifies, and
   hands off.

Every physical agent receives only its mapped logical-specialist assignments,
and every logical specialist receives only its exact capabilities and scopes.
Capabilities add methods, evidence requirements, stop conditions, audit
domains, and loop controls while inheriting the canonical role's permissions;
they never grant tools, writes, delegation, approvals, or release authority.
Every logical specialist returns one `jstack.specialist.result.v1` plus
metadata-only `jstack.specialist.telemetry.v1`. The Lead calls
`jstack_specialist_result` with the exact Team Plan receipt, specialist ID,
physical-agent ID, canonical role, capability IDs, and scope for every
`dynamicReceiptAssignments` entry. The exact `root-cause-investigator` result
also carries its in-memory `investigation_contract`; the signed receipt keeps
only digest/count certification metadata. The Lead then calls
`jstack_specialist_handoff_check` with the same receipt and ordered
role/capability projection. Do not retain raw prompts, messages, tool
arguments, command/model output, source contents, or secrets. Missing, stale,
partial, scope-drifted, permission-unsafe, capability-drifted, duplicate, or
contradictory logical-specialist receipt sets block handoff until the Lead
reconciles them with evidence.

If multi-agent tools are unavailable, state `No subagents deployed:` with the
concrete reason. Retain `team_mode="full-team"` in planning and apply its
evidence rubric while one Lead performs the work.

`/jstack-loop` remains a separate persistent orchestration workflow. For an
active loop, obey its frozen delivery-mode and capability contract; do not
inject a dynamic Team Plan or v2 handoff receipt into persisted Loop state
unless that Loop response explicitly exposes the matching versioned binding.

For production/release work, the Lead declares `core` plus every applicable
product surface, risk tier, and immutable deployment fingerprint with
`jstack_launch_assess` on the clean integrated candidate, then reconciles
detected omissions. Security, QA, DevOps, Product, Reviewer, Architect, and
Documentation collect bounded structured requirement evidence; accountable
humans own legal and merchant decisions. The Lead alone registers and
finalizes. JStack derives outcomes. High-risk security requires an independent
scanner; critical risk also requires independent human review and permits no
waiver. Missing, stale, failed, incomplete, truncated, or drifted evidence
blocks synthesis. Public-web, commercial, payment, and regulated-data profiles
also require a current release-profile audit.

JStack never generates approval challenges, tokens, signing commands, or
terminal approval steps. Only the Lead may perform repository, Git, provider,
deployment, or production actions, and only within the user's explicit request
plus normal Codex/provider permissions. Specialists remain unable to perform
those actions. Staffing approval, readiness, and handoff do not widen scope.
