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
8. On a clean committed production candidate, declare applicable product
   surfaces, register typed launch evidence, and finalize a launch receipt.
9. Run release readiness when requested; it reports evidence and does not
   execute a release.
10. Perform external actions only within explicit user scope and normal
   Codex/provider permissions. JStack adds no token or terminal ceremony.
11. Save handoff context and document residual risk.

## Production Controls

- policy-as-code
- agent coordination packet
- file ownership map
- protected-path checks
- diff hygiene
- commit-bound QA receipts for every discovered command
- complete current-tree and release-history secret evidence
- explicit `core` plus every applicable launch surface
- a current passing launch receipt with typed per-control evidence
- a release-profile audit for public-web, commercial, payment, and
  regulated-data profiles
- explicit base and environment-specific approval reference
- rollback plan
- canary or monitoring plan
- quant/backtest evidence gates

Repository, Git, provider, release, deployment, and production actions remain
separate from evidence collection. Task scope and the host/provider's normal
permissions govern execution. Release readiness, audit results, specialist
handoff, and loop/program completion remain evidence or workflow state. See
[Host-Native Action Safety](action-safety.md).

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
