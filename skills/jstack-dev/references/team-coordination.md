# Team Coordination

## Composition model

Team Composer selects the smallest competent logical specialist set from
inspected task facts, risk, mode, profile, scope, and policy. Every specialist
maps to one of the stable canonical authority roles. Compatible logical
specialists may share one physical agent; mandatory independent functions may
not. Full Team means complete material function coverage, never a fixed roster.

Lead owns scope, contradiction resolution, synthesis, verification, and
handoff. Exactly one Team Plan assignment may receive the source-labelled
bounded write scope. Every other logical specialist is read-only. A specialist
title, capability, physical-agent allocation, plan, or receipt cannot expand
canonical-role authority.

## Packet contract

`jstack_team_plan` returns a signed `jstack.team-plan.v1`, a session-bound
`jstack.team-plan-receipt.v1`, and an exact
`jstack.team-coordination.v2` packet. The packet binds:

- Team Plan ID and digest;
- resolved operating mode and preserved requested task mode;
- physical agents, logical specialists, canonical roles, and separation edges;
- the single file-ownership map;
- evidence contracts, conflict rule, stop conditions, verification, and
  handoff gates;
- `authorityEffect: none`.

The same result exposes a `hostContract`, `securityProviderPlan`, and
`professionalDeliveryPipeline`. Their digests are signed into the Unified Team
receipt and recomputed at dispatch. They describe supported host execution,
proportionate security evidence, and phase order; none grants authority.

`jstack_dispatch_check` must receive the complete returned `team` object and
the exact packet. Altered, regenerated, stale, preview-only, shadow, boolean,
or legacy packets cannot validate Team Composer dispatch.

## Ownership

Normalize scopes as repository-relative paths. Reject the repository root,
absolute paths, `..`, invented placeholders, untrusted/inferred scope facts,
unknown assignments, missing writer scopes, and overlaps. `implement` and
`fix` require a source-labelled `authorized_write_scopes` Context Readiness
fact. Other task modes carry no source write scope.

Shared files remain Lead-owned or are edited serially. If work cannot be split
cleanly, use one writer.

## Evidence

Each selected logical specialist, including Lead, returns
`jstack.specialist.result.v1` with status, scope handled, typed evidence,
findings, changes, blockers, residual risk, skipped checks, and one recommended
action. Every assignment- and capability-required evidence kind must appear. A
result marked success cannot contain an open blocker or blocking finding.

Each result also carries `jstack.specialist.telemetry.v1`: run/trace/span IDs,
timestamps, status, tool names and statuses, evidence references, derived input
and output digests, duration, and optional token counts. `rawContentStored` is
always false. Raw prompts, messages, tool arguments, command or model output,
source contents, credentials, and secrets are forbidden.

The Lead calls `jstack_specialist_result` for every
`dynamicReceiptAssignments` entry with the exact Team Plan receipt,
specialist ID, physical-agent ID, canonical role, capability IDs, and write
scope. The Lead then calls `jstack_specialist_handoff_check` with that Team
Plan receipt and the ordered role/capability projection. Duplicate canonical
roles are valid because evidence coverage is keyed by logical specialist.
Missing, duplicate, stale, tampered, physical-agent-drifted,
capability-drifted, permission-unsafe, overlapping, blocked, or contradictory
sets fail. Contradictions need a named `resolutionKey` and evidence-backed
Lead resolution. The handoff receipt proves current structural contract
consistency, not semantic truth.

Capability packs inherit the selected canonical role. They never grant new
tools, write scope, delegation, approvals, or release authority. The Lead
reconciles disagreement using reproduction, source evidence, project rules,
and safety gates.

Specialists do not spawn descendants, create repositories, change remotes,
commit, push, create pull requests, merge, tag, release, deploy, reset history,
delete data, alter production, or claim overall completion.

## Delivery sequence

Follow required phases from the exact `professionalDeliveryPipeline` in order:
plan, implement, review, QA, browser QA, security, and evidence. Only the exact
Team Plan writer may mutate source during implement. A candidate change makes
all candidate-bound phase evidence stale. Do not regenerate the pipeline,
replace unsupported host capabilities, or treat evidence completeness as
permission for an external action.
