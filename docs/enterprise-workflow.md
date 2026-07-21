# Enterprise JStack Workflow

## Commands

1. `/j-stack-dev`: single Lead Engineer, no subagents.
2. `/jstack-subagents`: Lead Engineer plus the right specialist team, normally
   2-3 specialists.
3. `/jstack-full-team`: full 11-role JStack team for major or explicitly
   requested full-team work.

## Gates

1. Classify task risk.
2. Restore context and read project instructions.
3. Create an enterprise plan.
4. Build a team plan and coordination packet when risk justifies specialists.
5. Run policy and preflight checks.
6. Implement the smallest coherent change.
7. Review, test, QA, and security-check proportionally to risk.
8. Run release readiness only when a readiness assessment is explicitly
   requested; it never authorizes execution.
9. Default to local-only. For each protected action, use exact challenge,
   independent human signature, authorization, fresh provider observation,
   destructive one-time consumption, and one execution before permit expiry.
10. Save handoff context and document residual risk.

## Production Controls

- policy-as-code
- agent coordination packet
- file ownership map
- protected-path checks
- diff hygiene
- commit-bound QA receipts for every discovered command
- complete current-tree and release-history secret evidence
- explicit base and environment-specific approval reference
- exact signed one-action authorization bound to provider, owner, repository,
  visibility, remote URL, branch/tag, full commit, target environment, current
  Git/workspace/policy/remote state, and MCP session
- fresh provider observation and one-time permit consumption
- rollback plan
- canary or monitoring plan
- quant/backtest evidence gates

Repository creation, remote add/change, commit, push, pull-request creation,
merge, tag, release, deployment, and production mutation are separate actions.
Task verbs, phase/remediation approval, release readiness, audit results,
specialist handoff, and loop/program completion are evidence or workflow state,
not authority. See [External-Action Authorization Boundary](external-action-boundary.md).

## Mastery Path

0. Safe Operator
1. JStack Reader
2. Scoped Maintainer
3. Debugger and Test Author
4. MCP and Policy Engineer
5. Workflow Product Engineer
6. Packaging and Release Engineer
7. Security and Reliability Auditor
8. JStack Architect
9. Staff Maintainer and Auditor
