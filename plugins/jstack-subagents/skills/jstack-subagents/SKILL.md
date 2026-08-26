---
name: jstack-subagents
description: JStack specialist-team workflow. Use when the user invokes /jstack-subagents or explicitly asks to deploy the right subagent team, normally two or three specialists.
metadata:
  short-description: Deploy the right JStack specialist team
---

# JStack Subagents

Treat this command as explicit user approval to deploy subagents when multi-agent tools are available.

Default behavior:

1. Keep the Lead Engineer accountable for scope, synthesis, implementation decisions, verification, and handoff.
2. Deploy the Team Composer's smallest competent logical specialist set,
   normally mapped to two or three physical specialist agents.
3. Permit a fourth physical agent only when a mandatory risk floor requires
   independence; never drop expertise or collapse independence to fit a budget.
4. Keep specialists read-only except the one exact Team Plan writer with a
   source-labelled bounded scope.
5. Treat specialist titles, capabilities, plans, and receipts as
   non-authorizing views of stable canonical roles.

Before repository inspection, durable-memory reads, planning, or
side-effecting tools, call
`jstack_prompt_compile(stage="intent", workflow_mode="jstack-subagents",
raw_request=exact_user_request)`. Preserve the exact Stage A contract and
receipt; they grant no execution authority or additional staffing authority.

Before dispatch, require the exact signed `unifiedTeamPlan` and returned
`jstack.team-coordination.v2` packet. They bind the physical agents, logical
specialists, canonical roles, scopes, independence, evidence, and stop rules.

After the approved Prompt Compiler gate below, pass the complete returned
`team` object and exact `dynamicCoordinationPacket` to
`jstack_dispatch_check`; a boolean, altered, or regenerated packet is invalid.
Use `jstack_plan` with
`team_mode="smart-subagents"`, the current `context_readiness_receipt`, and
its matching `normalizedBrief` as `context_brief`, plus the resolved learning
mode: explicit `off`, `coach`, or `assessment`, otherwise `embedded`. Pass the
same receipt and brief to `jstack_team_plan`.
Proceed only when `executionSource="team-composer"` and
`dispatchEligible=true`. A blocked, shadow, or preview-only plan stops; never
fall back silently. The legacy `agents` array is not the active roster. The MCP
plans and validates; platform multi-agent tools perform actual dispatch,
collection, and closure.

Read the receipt-bound `methodologyPlan` before dispatch. Apply only selected
JStack-native methodology records and pass their phases, output contracts,
evidence, and stop conditions to the mapped logical specialists. An empty
selection is valid. Never run upstream gstack skills or prompt templates
directly. Methodologies inherit task mode, scope, canonical-role permissions,
and normal provider controls; they grant no new authority or persistence.

When `root-cause-investigation` is selected, sequence it before any writer.
For `fix` or an investigation-selected `implement`, call
`jstack_dispatch_check(dispatch_phase="investigation")` and dispatch only the
returned read-only `executionSlice`; no source edit is allowed. The exact
root-cause assignment returns `jstack.investigation.v1` through
`jstack_specialist_result`. Three consecutive falsified or inconclusive
hypotheses require a later revised execution trace, genuinely changed
hypotheses, explicit unresolved state, and a stop; a fourth random patch or
hypothesis is invalid. Call
`jstack_dispatch_check(dispatch_phase="remediation",
investigation_receipt=...)` only for an established cause on the unchanged
candidate, then dispatch only the returned remediation slice under the
original Team Plan scope. `diagnose-only`, unresolved evidence, staffing
approval, and a receipt do not grant fix authority.

Dispatch physical agents exactly as mapped and give each only its logical
specialist assignments. Capabilities add methods, evidence requirements, stop
conditions, audit domains, and loop controls; they never grant tools, writes,
delegation, approvals, or release authority. Each logical specialist returns a
`jstack.specialist.result.v1` object and metadata-only
`jstack.specialist.telemetry.v1`. The Lead calls `jstack_specialist_result`
with the exact Team Plan receipt, specialist ID, physical-agent ID, canonical
role, capability IDs, and scope for every `dynamicReceiptAssignments` entry,
and the exact `root-cause-investigator` call also carries its in-memory
`investigation_contract`; the signed receipt retains only its digest-only
certification. The Lead then calls `jstack_specialist_handoff_check` with the
same receipt and ordered
role/capability projection. Raw prompts, messages,
tool arguments, command/model output, source contents, and secrets are
forbidden in telemetry. Missing, stale, partial, conflicting, permission-unsafe,
or capability-drifted receipts block handoff; contradictions need an explicit
evidence-backed Lead resolution.

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
source-attributed facts, separate assumptions, and only material open
questions. Ask no more than the returned three questions in normal chat, with
the reason and recommended default for each. Clear prompts ask nothing. Reuse
answers and do not repeat unchanged questions. Low-risk defaults may continue
as disclosed assumptions; high-risk material defaults need explicit
conversational confirmation. Confirm only already displayed assumptions and
never apply a new default batch in the same call. Do not run a duplicate
`jstack_context_readiness` round. This gate never asks for a token, signer,
digest, or terminal paste. When context is ready, display the complete
`renderedCodexPrompt` and wait for explicit approval or requested changes.
Stop before team planning or dispatch. Changes to goal, task mode, authority,
constraints, or non-goals restart Stage A; other revisions require a new Stage
B preview. After approval, repeat Stage B with the exact internal
`promptPreviewReceipt` and approval bound to the displayed prompt digest.
Never infer approval or ask the user to handle receipt values. Use only the
approved response's receipts downstream. For `implement` or `fix`, include a
source-labelled `authorized_write_scopes` context fact containing a bounded
repository-relative path or JSON string array derived from inspection. It
constrains one writer and grants no action authority.

The one Team Plan writer may implement only in its exact scope. If mandatory
independence exceeds this mode's physical-agent limit, stop and recommend
`/jstack-full-team`; never omit a required logical specialist.

`/jstack-loop` remains a separate persistent orchestration workflow. For an
active loop, obey its frozen delivery-mode and capability contract; do not
inject a dynamic Team Plan or v2 handoff receipt into persisted Loop state
unless that Loop response explicitly exposes the matching versioned binding.

No two editing agents may own the same file or module. If scope cannot be split
cleanly, use one Builder. The Lead Engineer resolves conflicts using evidence,
reproduction, project rules, and safety gates.

For production/release work, the Lead declares `core` plus every applicable
product surface, risk tier, and immutable deployment fingerprint with
`jstack_launch_assess` on the clean integrated candidate, then reconciles
detected omissions. Security owns security requirements, QA owns
interaction/device/delivery assertions, DevOps owns transport and
observability, Product owns findability/analytics semantics, and accountable
humans own legal and business facts. Specialists return bounded structured
artifacts; only the Lead registers and finalizes the exact requirements. JStack
derives outcomes. High-risk security requires an independent scanner; critical
risk also requires independent human review and permits no waiver. Missing or
failed blocker/required evidence blocks handoff. Public-web, commercial,
payment, and regulated-data profiles also require a release-profile audit.

If multi-agent tools are unavailable, state `No subagents deployed:` with the
concrete reason. Retain `team_mode="smart-subagents"` in planning and apply
its evidence rubric while one Lead performs the work.

JStack never generates approval challenges, tokens, signing commands, or
terminal approval steps. Only the Lead may perform repository, Git, provider,
deployment, or production actions, and only within the user's explicit request
plus normal Codex/provider permissions. Specialists remain unable to perform
those actions. Staffing approval, readiness, and handoff do not widen scope.
