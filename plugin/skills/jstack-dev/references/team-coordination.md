# Team Coordination

## Roles

The full roster is Lead, Architect, Investigator, Builder, Reviewer, QA,
Security, DevOps/Release, Product/UX, Quant/Backtest, and Documentation/Handoff.

Lead owns scope, assignments, synthesis, final edits, verification, and
handoff. Builder may edit one assigned disjoint implementation scope.
Documentation may edit assigned documentation. Every other role is read-only.

## Packet Contract

The packet uses exact keys: `goal`, `riskClass` (array), `mode`,
`rolesUsed`, `rolesNotUsed`, `readWritePermissions`,
`fileOwnershipMap`, `capabilityPlan`, `evidenceContract`, `conflictRule`,
`stopConditions`, `verificationGate`, and `handoffGate`.

Each assignment states:

- one bounded question or deliverable
- read-only or write permission
- exact path/module scope for writers
- exact versioned capability IDs, methods, required evidence, and stop conditions
- evidence expected
- actions the specialist must not perform

`jstack_dispatch_check` must receive the packet object and proposed agents.
A packet-presence boolean is not evidence.

## Ownership

Normalize scopes as repository-relative paths. Reject absolute paths, `..`,
unknown roles, unauthorized writers, missing writer scopes, and overlaps.
Ancestor and glob overlap count: `src`, `src/auth`, and `src/**` cannot be
concurrent owners.

Shared files remain Lead-owned or are edited serially. If work cannot be split
cleanly, use one writer.

## Evidence

Each routed role, including Lead, returns `jstack.specialist.result.v1` with
status, scope handled, typed evidence, findings, changes, blockers, residual
risk, skipped checks, and one recommended action. Every capability-required
evidence kind must appear. A result marked success cannot contain an open
blocker or blocking finding.

Each result also carries `jstack.specialist.telemetry.v1`: run/trace/span IDs,
timestamps, status, tool names and statuses, evidence references, derived input
and output digests, duration, and optional token counts. `rawContentStored` is
always false. Raw prompts, messages, tool arguments, command or model output,
source contents, credentials, and secrets are forbidden.

The Lead calls `jstack_specialist_result` for every exact role/capability
assignment, then `jstack_specialist_handoff_check`. The latter rejects missing,
duplicate, stale, tampered, capability-drifted, permission-unsafe, overlapping,
blocked, or contradictory receipt sets. Contradictions need a named
`resolutionKey` and an evidence-backed Lead resolution. The issued handoff
receipt proves structural/current contract consistency, not semantic truth.

Capability packs inherit the selected role. They never grant new tools, write
scope, delegation, approvals, or release authority. The Lead reconciles
disagreement using reproduction, source evidence, project rules, and safety
gates.

Specialists do not spawn descendants, create repositories, change remotes,
commit, push, create pull requests, merge, tag, release, deploy, reset history,
delete data, alter production, or claim overall completion.
