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
8. Run release readiness only when release/deploy is explicitly requested.
9. Save handoff context and document residual risk.

## Production Controls

- policy-as-code
- agent coordination packet
- file ownership map
- protected-path checks
- diff hygiene
- commit-bound QA receipts for every discovered command
- complete current-tree and release-history secret evidence
- explicit base and environment-specific approval reference
- rollback plan
- canary or monitoring plan
- quant/backtest evidence gates

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
