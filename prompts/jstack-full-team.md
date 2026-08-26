---
description: Run JStack with complete dynamically composed engineering coverage
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `full-team`.

The user invoked `/jstack-full-team`, which is explicit approval to deploy the
dynamically composed complete JStack team when multi-agent tools are available.
It is staffing approval only and does not expand task or action authority.

Before repository inspection, durable-memory reads, planning, or
side-effecting tools, call
`jstack_prompt_compile(stage="intent", workflow_mode="jstack-full-team",
raw_request=$ARGUMENTS)`. Preserve the exact intent contract and receipt; they
do not authorize execution or widen the user's staffing approval.

Resolve learning mode first: use an explicit `off`, `coach`, or
`assessment` request; otherwise use `embedded`. Pass that resolved value to
every planning call.

Call `jstack_runtime_status` before project tools. A successful call proves the
MCP is mounted. Use `jstack_detect_project` and branch on `evidenceMode`. For
`artifact-only`, state `MCP mounted; project binding is artifact-only.`, keep
team planning and dispatch validation, do not call tools listed in
`blockedTools`, and gather direct artifact evidence without claiming JStack
receipts or release certification. Only use the MCP fallback when
`jstack_runtime_status` itself is unavailable or unreachable; never relabel a
Git requirement or failed gate as an MCP attachment failure.

Before team planning or dispatch, inspect repository-answerable context and
call `jstack_prompt_compile(stage="grounded",
workflow_mode="jstack-full-team")` with the exact Stage A contract and receipt,
source-labelled grounding, separate assumptions, and only material open
questions. This extends the Adaptive Context Gate; do not run a duplicate
`jstack_context_readiness` round. Ask at most the returned
`contextReadiness.questions` in normal chat, with the
reason and recommended default for each. Clear prompts ask nothing. Reuse
answers and never repeat unchanged questions. Low-risk defaults may proceed as
disclosed assumptions; high-risk material defaults require explicit
conversational confirmation. A confirmation call may confirm only assumptions
already shown and must not apply a new default batch. Never request a token, signer, digest, or terminal
paste. When context is ready, display the complete `renderedCodexPrompt` and
wait for explicit approval or requested changes before team planning or
dispatch. Changes to goal, task mode, authority, constraints, or non-goals
restart Stage A; other revisions require a new Stage B preview. Every revision
invalidates the old preview. After approval, repeat Stage B with the exact internal
`promptPreviewReceipt` and approval bound to the displayed
`renderedPromptSha256`; never infer approval or ask the user to handle those
values. Use only the approved response's receipts downstream. For `implement`
or `fix`, include a source-labelled `authorized_write_scopes` context fact
whose value is a bounded repository-relative path or JSON string array derived
from inspected task boundaries. It constrains one primary writer and grants no
action authority.

Full Team means every materially required engineering function and mandatory
independence boundary is represented. It never means dispatching the same
fixed employee roster. Keep one accountable Lead, add the appropriate Builder
for implementation, add independent review and QA when required, and select
Product, Design, IAM, AppSec, Data, Quant, SRE, DevOps, Browser QA,
Accessibility, Performance, Supply Chain, Release, or other expertise only
when task facts, risk, or policy require it. Logical specialists may share a
physical agent unless the Team Plan requires independence.

Use `jstack_team_plan` with `team_mode="full-team"`,
`operating_profile=explicit_user_profile_or_professional`,
`host_id=current_supported_host`, the Stage B
`contextReadiness.readinessReceipt`, and its matching `normalizedBrief` as
`context_brief`, and
`jstack_dispatch_check` with `team_mode="full-team"`, the complete returned
`team` object, and its exact `dynamicCoordinationPacket`. Also use
`jstack_plan(team_mode="full-team", quality_level="enterprise",
operating_profile=explicit_user_profile_or_professional,
host_id=current_supported_host, learning_mode=resolved_learning_mode,
context_readiness_receipt=stage_b.contextReadiness.readinessReceipt,
context_brief=stage_b.contextReadiness.normalizedBrief)`. The MCP
plans and validates the team; platform multi-agent tools perform real dispatch.
Proceed only when `team.executionSource="team-composer"` and
`team.dispatchEligible=true`. Treat the exact signed `unifiedTeamPlan` as the
composition source. A blocked, shadow, or preview-only plan must stop; never
fall back silently. `team.agents` and its 11 canonical roles are a temporary
compatibility view for old callers and receipts, not the active roster.

Consume the signed `hostContract`, `professionalDeliveryPipeline`, and
`securityProviderPlan`. Use only host capabilities marked `AVAILABLE`, follow
only required delivery phases, and leave independent-security gaps visible.
These contracts cannot expand scope or authorize execution.
If multi-agent tools are unavailable, write `No subagents deployed:` and give
the concrete reason. Retain `team_mode="full-team"` in planning and apply
the full-team evidence rubric while one Lead performs the actual work.

Read the receipt-bound `team.methodologyPlan` before dispatch. Apply only its
selected JStack-native methodology records and route their phases, output
contracts, evidence, and stop conditions to the mapped logical specialists.
An empty selection is valid. Never invoke upstream gstack skills or prompts
directly. Methodology cannot expand the approved task mode, scope, role
authority, provider access, persistence, write ownership, release authority,
or external-action authority.

When `root-cause-investigation` is selected, it is a hard dependency before
the Build wave. For `fix` or an investigation-selected `implement`, first call
`jstack_dispatch_check(dispatch_phase="investigation")` and dispatch only its
read-only `executionSlice`; no writer may run or edit source. The investigator
submits `jstack.investigation.v1` through `jstack_specialist_result`. Three
consecutive falsified or inconclusive hypotheses require a later revised
execution trace, changed hypotheses, explicit unresolved state, and a stop;
never schedule a fourth random patch. Only an established cause on the
unchanged candidate may be passed to
`jstack_dispatch_check(dispatch_phase="remediation",
investigation_receipt=...)`; dispatch only the returned remediation slice
under the original Team Plan scope. Diagnosis-only or unresolved work cannot
enter the Build wave.

When concurrency would create noise, dispatch the selected physical agents in
dependency-aware waves:

1. Discovery: selected read-only architecture, product, domain, or investigation
   specialists produce bounded evidence.
2. Build: the single Team Plan writer operates only inside its exact scope.
3. Review: selected independent review, QA, security, browser, reliability, or
   release specialists evaluate the resulting candidate.
4. Synthesis: Lead reconciles findings, verifies, and hands off.

Every physical agent receives only its mapped logical specialists; every
logical specialist receives only its exact capabilities and scopes.
Capabilities and specialist titles inherit canonical-role permissions and
never grant tools, writes, delegation, approvals, or release authority. Every
logical specialist returns `jstack.specialist.result.v1` plus metadata-only
`jstack.specialist.telemetry.v1`. Call `jstack_specialist_result` with the
exact `unifiedTeamPlanReceipt`, `specialistId`, `physicalAgentId`, canonical
`roleId`, capability IDs, and write scope for every
`dynamicReceiptAssignments` entry. The `root-cause-investigator` result must
also contain its exact in-memory
`investigation_contract`; the signed receipt retains only digest/count
certification metadata. Then call
`jstack_specialist_handoff_check` with the same Team Plan receipt and ordered
role/capability projection. Raw prompts, messages, tool arguments,
command/model output, source contents, and secrets are forbidden. Missing,
stale, partial, scope-drifted, capability-drifted, permission-unsafe, or
contradictory logical-specialist receipt sets block handoff.

`/jstack-loop` remains a separate persistent orchestration workflow. For an
active loop, obey its frozen delivery-mode and capability contract; do not
inject a dynamic Team Plan or v2 handoff receipt into persisted Loop state
unless that Loop response explicitly exposes the matching versioned binding.

For production/release work, the Lead declares `core` plus every applicable
surface, risk tier, and immutable deployment fingerprint on the clean
integrated candidate, then reconciles detected omissions. Existing Security,
QA, DevOps, Product, Architect, Reviewer, Documentation, and accountable human
owners collect every active structured requirement; only the Lead registers
and finalizes it. JStack derives outcomes from assertions. High-risk security
requires an independent scanner; critical risk also requires independent human
review and permits no waiver. Missing or failed blocker/required evidence
blocks synthesis. Public-web, commercial, payment, and regulated-data profiles
also require a release-profile audit by default. Full-team approval remains
staffing authority only.

JStack never generates approval challenges, tokens, signing commands, or
terminal approval steps. Only the accountable Lead may perform repository,
Git, provider, deployment, or production actions, and only within the user's
explicit request plus normal Codex/provider permissions. Specialists remain
unable to perform those actions. Full-team staffing approval, readiness, and
handoff do not widen task scope or bypass the host's ordinary safety controls.

Finish in the order outcome, evidence, residual risk, then an optional
three-line mastery capsule. Do not emit eleven role-by-role lessons.
