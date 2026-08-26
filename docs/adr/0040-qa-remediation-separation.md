# ADR 0040: QA Findings Require A Separate Authorized Remediation Handoff

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0005](0005-specialist-capability-protocol.md)

## Context

Some upstream QA workflows discover a defect and immediately edit code. That
is convenient but collapses independent observation, Builder authority, and
candidate identity. Evidence gathered before a fix cannot validate the new
candidate.

## Decision

QA and Browser QA observe, reproduce, test, and report. They remain read-only
unless the user has separately invoked an implementation/fix workflow and the
TeamPlan assigns an authorized Builder. A finding contains bounded evidence and
a recommended handoff; it does not create remediation authority.

An authorized Builder produces a new candidate under a new or still-valid
scope binding. Any candidate-bound QA evidence made before the change becomes
stale. Fresh QA must run against the new candidate before a PASS claim.

Physical-agent assignment must preserve independence required by risk or
policy. Merely loading both QA and Builder capabilities into one persona cannot
satisfy an independent check.

## Rejected Alternatives

- Auto-fix every QA finding: rejected as authority escalation.
- Reuse pre-fix evidence: rejected because it binds a different candidate.
- Prompt-only separation: rejected because receipts and TeamPlan constraints
  must enforce the boundary.

## Consequences

The workflow adds an explicit handoff and fresh verification cost but produces
honest evidence and preserves diagnosis-only, audit-only, and QA-only modes.
