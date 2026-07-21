# Agent Coordination Packet

## Goal

<!-- One-sentence user objective. -->

## Risk Class

<!-- trivial | normal | architecture | ui_product | security_compliance | data_financial | production_release -->

## Mode

<!-- single-lead | smart-subagents | full-team -->

## Role Assignments

| Role | Used? | Why Needed | Read/Write | Scope |
| --- | --- | --- | --- | --- |
| Lead Engineer | Yes | Owns scope, synthesis, verification, handoff | Write | Overall |
| Architect |  |  | Read-only |  |
| Code Investigator |  |  | Read-only |  |
| Builder |  |  | Assigned write scope only |  |
| Reviewer |  |  | Read-only |  |
| QA Engineer |  |  | Read-only |  |
| Security Engineer |  |  | Read-only |  |
| DevOps / Release Engineer |  |  | Read-only |  |
| Product / UX Reviewer |  |  | Read-only |  |
| Quant / Backtest Reviewer |  |  | Read-only |  |
| Documentation / Handoff Writer |  |  | Docs only when assigned |  |

## File Ownership Map

| Path/Module | Owner | Write Allowed? | Notes |
| --- | --- | --- | --- |

## Specialist Evidence Contract

Every specialist must return:

- scope handled
- files, commands, screenshots, logs, reports, or data reviewed
- findings or changes
- blockers
- residual risk
- recommended next action

## Conflict Rule

Evidence beats opinion. Reproduction beats speculation. Project rules beat
generic best practice. Safety gates beat speed. Lead Engineer decides and
documents unresolved risk.

## Stop Conditions

- missing exact signed action authorization
- repository, Git, release, deployment, or production action implied by broad
  task, staffing, phase, or remediation approval
- secrets exposed
- release blocker disagreement
- unclear failing tests
- file ownership overlap
- scope expands beyond request
- evidence is insufficient for the claim

## Verification Gate

<!-- Tests, lint, typecheck, build, browser QA, security scan, backtest evidence, logs, screenshots. -->

## Handoff Gate

Final handoff must include:

- files changed
- checks run and results
- specialist findings reconciled
- unresolved risks
- next steps
