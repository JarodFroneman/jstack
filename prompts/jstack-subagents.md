---
description: Run JStack with the right specialist subagent team
argument-hint: [GOAL]
---

Apply the custom JStack enterprise development workflow to this task.

Goal:
$ARGUMENTS

Mode: `smart-subagents`.

The user invoked `/jstack-subagents`, which is explicit approval to deploy
subagents for this task when multi-agent tools are available.

Before repository inspection, durable-memory reads, planning, or
side-effecting tools, call
`jstack_prompt_compile(stage="intent", workflow_mode="jstack-subagents",
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
workflow_mode="jstack-subagents")` with the exact Stage A contract and receipt,
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
from the inspected task boundary. It constrains one primary writer and grants
no action authority.

Use the Team Composer's smallest competent logical specialist set. The normal
topology is one accountable Lead plus two or three physical specialist agents;
a mandatory risk floor may use the mode's fourth physical slot. Logical
specialist count is not physical-agent count. Do not select a fixed job-title
list, and do not omit architecture, IAM, AppSec, Quant, QA, release, or other
independent expertise when the signed Team Plan requires it.

Use `jstack_team_plan` with `team_mode="smart-subagents"`,
`operating_profile=explicit_user_profile_or_professional`,
`host_id=current_supported_host`, the Stage B
`contextReadiness.readinessReceipt`, and its matching `normalizedBrief` as
`context_brief`, and
`jstack_dispatch_check` with `team_mode="smart-subagents"`, the complete
returned `team` object, and its exact `dynamicCoordinationPacket`. Also use
`jstack_plan(team_mode="smart-subagents", quality_level="enterprise",
operating_profile=explicit_user_profile_or_professional,
host_id=current_supported_host, learning_mode=resolved_learning_mode,
context_readiness_receipt=stage_b.contextReadiness.readinessReceipt,
context_brief=stage_b.contextReadiness.normalizedBrief)`.
Proceed only when `team.executionSource="team-composer"` and
`team.dispatchEligible=true`. Treat `unifiedTeamPlan`, its selected logical
specialists, physical allocation, exact write scope, independence requirements,
and evidence contracts as the execution contract. A blocked, shadow, or
preview-only plan must stop; never fall back silently. `team.agents` is a
temporary legacy compatibility view, not the active roster.

Consume the signed `hostContract`, `professionalDeliveryPipeline`, and
`securityProviderPlan`. Use only host capabilities marked `AVAILABLE`, follow
only required delivery phases, and leave independent-security gaps visible.
These contracts cannot expand scope or authorize execution.

Read the receipt-bound `team.methodologyPlan` before dispatch. Apply only its
selected JStack-native methodology records and give their phases, output
contracts, evidence, and stop conditions to the mapped logical specialists.
An empty selection is valid. Do not run upstream gstack skills or prompts
directly. A methodology never changes task mode, scope, role authority, tool or
provider access, persistence, write ownership, or external-action authority.

When `root-cause-investigation` is selected, sequence it before any writer.
For `fix` or an investigation-selected `implement`, call
`jstack_dispatch_check(dispatch_phase="investigation")` and dispatch only the
returned read-only `executionSlice`. The root-cause assignment returns
`jstack.investigation.v1` through `jstack_specialist_result`, with no source
changes. Three consecutive falsified or inconclusive hypotheses require a
later revised trace, genuinely changed hypotheses, explicit unresolved state,
and a stop; a fourth random patch is invalid. Call
`jstack_dispatch_check(dispatch_phase="remediation",
investigation_receipt=...)` only for an established cause on the unchanged
candidate, then dispatch only that remediation slice under the original Team
Plan scope. `diagnose-only`, unresolved evidence, staffing approval, and a
receipt do not grant fix authority.

Dispatch the physical agents exactly as mapped and give each only its assigned
logical specialists. Capabilities add method, evidence requirements, stop
conditions, audit domains, and loop controls; they never grant tools, writes,
delegation, approvals, or release authority. One assignment may own the exact
bounded source scope; every other assignment is read-only. Each logical
specialist returns `jstack.specialist.result.v1` plus metadata-only
`jstack.specialist.telemetry.v1`. Call `jstack_specialist_result` with the
exact `unifiedTeamPlanReceipt`, `specialistId`, `physicalAgentId`, canonical
`roleId`, capability IDs, and write scope for every
`dynamicReceiptAssignments` entry. The `root-cause-investigator` result must
additionally carry its exact
in-memory `investigation_contract`; the signed receipt keeps only the
digest-only certification. Then call
`jstack_specialist_handoff_check` with the same Team Plan receipt and the
ordered role/capability projection. Missing, stale, partial, scope-unsafe,
capability-drifted, or contradictory logical-specialist receipts block
handoff. Do not store raw prompts, messages, tool arguments, command/model
output, source contents, or secrets.

The MCP plans and validates the team; it does not spawn one. Use platform
multi-agent tools for actual dispatch, collection, and closure. Finish in the
order outcome, evidence, residual risk, then an optional three-line mastery
capsule.

If mandatory independence needs more physical agents than this mode permits,
the Team Composer fails closed. Recommend `/jstack-full-team`; never drop a
required specialist or merge an independence boundary to fit the mode.

If multi-agent tools are unavailable, write `No subagents deployed:` and give
the concrete reason. Retain `team_mode="smart-subagents"` in planning and
apply its evidence rubric, while one Lead performs the actual work.

`/jstack-loop` remains a separate persistent orchestration workflow. For an
active loop, obey its frozen delivery-mode and capability contract; do not
inject a dynamic Team Plan or v2 handoff receipt into persisted Loop state
unless that Loop response explicitly exposes the matching versioned binding.

For production/release work, the Lead declares `core` plus every applicable
surface, risk tier, and immutable deployment fingerprint on the clean
integrated candidate, then reconciles detected omissions. Route every active
structured requirement through existing Security, QA, DevOps, Product,
Reviewer, and accountable human owners; only the Lead registers and finalizes
it. JStack derives outcomes from assertions. High-risk security requires an
independent scanner; critical risk also requires independent human review and
permits no waiver. Missing or failed blocker/required evidence blocks handoff.
Public-web, commercial, payment, and regulated-data profiles also require a
release-profile audit by default. This adds no sixth command or new role.

JStack never generates approval challenges, tokens, signing commands, or
terminal approval steps. Only the accountable Lead may perform repository,
Git, provider, deployment, or production actions, and only within the user's
explicit request plus normal Codex/provider permissions. Subagents remain
unable to perform those actions. Staffing approval, readiness, and specialist
handoff do not widen task scope or bypass the host's ordinary safety controls.
