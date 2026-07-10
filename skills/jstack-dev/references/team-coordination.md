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
`fileOwnershipMap`, `evidenceContract`, `conflictRule`,
`stopConditions`, `verificationGate`, and `handoffGate`.

Each assignment states:

- one bounded question or deliverable
- read-only or write permission
- exact path/module scope for writers
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

Each specialist returns scope handled, files/commands/data inspected, findings
ordered by severity, explicit blockers, residual risk, and recommended action.
The Lead reconciles disagreement using reproduction, source evidence, project
rules, and safety gates.

Specialists do not spawn descendants, deploy, push, merge, reset history,
delete data, alter production, or claim overall completion.
