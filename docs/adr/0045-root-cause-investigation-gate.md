# ADR 0045: Root-Cause Evidence Precedes Remediation Dispatch

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0036](0036-methodology-adaptation.md)
- Preserves: [ADR 0040](0040-qa-remediation-separation.md)

## Context

The Stage 8 Root-Cause Investigation methodology routes diagnostic expertise
and evidence requirements, but a methodology record alone cannot prevent an
agent from repeatedly editing source until a test happens to pass. The
authoritative Unified Engineering OS specification requires the sequence
problem, observed behavior, reproduction, execution trace, hypothesis,
falsification attempt, root cause, then separately authorized remediation.

## Decision

Every `fix` task deterministically selects Root-Cause Investigation. When that
method is selected for an `implement` or `fix` Team Plan,
`jstack_dispatch_check` splits execution into two phases:

1. `investigation` returns only the read-only root-cause assignment and strips
   every write scope from the execution slice.
2. `remediation` requires the exact passing root-cause specialist receipt for
   the unchanged Git candidate.

The investigator supplies `jstack.investigation.v1` through the existing
`jstack_specialist_result` tool. The deterministic validator requires the
complete diagnostic flow, a falsification record, evidence references, no
source mutation, and an established cause before remediation can qualify.
Three consecutive falsified or inconclusive hypotheses require a changed
hypothesis, a later execution-trace revision bound to those attempts, and an
explicit unresolved `hypothesis-limit` stop. A fourth random cycle is
rejected.

The specialist receipt retains only
`jstack.investigation.certification.v1`: digests, counts, state, and authority
flags. It does not retain the raw investigation contract, source contents,
user prompt, secrets, or hidden reasoning. The certification is evidence, not
write or action authority. The approved task mode, Team Plan writer scope,
host permissions, and explicit user authority remain controlling.

## Enforcement Boundary

The MCP can reject invalid contracts, standard-dispatch bypasses, stale or
tampered receipts, unresolved causes, changed Git candidates, and
diagnosis-only remediation. It cannot intercept arbitrary native Codex edits
performed without the JStack workflow. Command and skill instructions
therefore require hosts to execute only the returned phase-specific
`executionSlice`.

Legacy direct dispatch plans have no signed methodology or task-mode binding,
so Stage 9 phase fields are rejected on that path. They retain their existing
compatibility behavior but cannot claim Stage 9 remediation qualification.

## Rejected Alternatives

- Prompt-only advice: rejected because it cannot produce a candidate-bound
  remediation gate.
- A new slash command or second router: rejected because Team Composer and the
  existing specialist-result path already own routing and evidence.
- Persisting a diagnostic journal in receipts: rejected for privacy, context,
  and hidden-reasoning risk.
- Automatically applying a probable fix: rejected because evidence never
  grants implementation authority.

## Consequences

Fix work incurs one explicit read-only diagnostic phase before source changes.
Clear feature implementation remains unaffected unless the approved goal
explicitly selects Root-Cause Investigation. Diagnosis-only work can establish
a cause but never becomes remediation. The public surface remains six
commands, 59 canonical MCP tools, and 52 frozen aliases.
