# gstack MCP

Local stdio MCP server for using the gstack workflow across Codex projects.

This is intentionally a narrow orchestration layer, not a generic shell runner.
It exposes safe, project-oriented tools that help an agent apply gstack patterns
consistently:

- `gstack_detect_project`
- `gstack_list_skills`
- `gstack_read_skill`
- `gstack_plan`
- `gstack_team_plan`
- `gstack_dispatch_check`
- `gstack_policy_check`
- `gstack_preflight`
- `gstack_health`
- `gstack_review`
- `gstack_security_audit`
- `gstack_qa`
- `gstack_context_save`
- `gstack_context_restore`
- `gstack_ship_check`
- `gstack_release_readiness`
- `gstack_quant_backtest_review`

## Design Rules

- No arbitrary shell command tool.
- No network calls.
- No destructive filesystem operations.
- Test/build execution is optional and restricted to commands discovered from
  project files such as `package.json`, `pyproject.toml`, `Cargo.toml`, or
  `go.mod`.
- Context save writes only to `~/.gstack/mcp-context`.
- gstack skills are read from `~/.gstack/repos/gstack`.

## Enterprise Enforcement

The server supports policy-as-code through a project policy file. Recommended
file names:

- `gstack.enterprise.json`
- `gstack.policy.json`
- `gstack.yml`
- `.gstack/gstack.enterprise.json`
- `.gstack/gstack.yml`

Templates live in `templates/`:

- `gstack.enterprise.json`
- `gstack.enterprise.yml`
- `pull_request_template.md`
- `release_checklist.md`
- `quant_backtest_review.md`

Use `gstack_policy_check` to load project policy and detect protected file
changes. Use `gstack_preflight` before substantial edits or handoff. Use
`gstack_release_readiness` before any production release. Use
`gstack_quant_backtest_review` before making trading, EA, or backtest
performance claims.

## Virtual Engineering Team

`gstack_team_plan` turns `/gstack-dev` into a controlled virtual engineering
team. It always keeps a Lead Engineer accountable and conditionally adds
specialists:

- Architect
- Code Investigator
- Builder
- Reviewer
- QA Engineer
- Security Engineer
- DevOps / Release Engineer
- Product / UX Reviewer
- Quant / Backtest Reviewer
- Documentation / Handoff Writer

Use `gstack_dispatch_check` before spawning several specialists or assigning
file edits. The default maximum is three specialists. More specialists require a
lead justification. Subagents are read-only by default, and only one agent may
own a given file/module write scope.

## Local Smoke Test

```bash
python3 /Users/jarodfroneman/.codex/mcp/gstack/smoke_test.py
```

## Install Into Codex

```bash
python3 /Users/jarodfroneman/.codex/mcp/gstack/install.py
```

The installer:

- copies this folder to `~/.codex/mcp/gstack`
- backs up `~/.codex/config.toml`
- adds `[mcp_servers.gstack]`

Restart Codex or open a new thread after installation.

## Operational Intent

Use this MCP as an enterprise project quality gate:

1. Classify the work by risk:
   - Trivial fix
   - Normal feature or bug
   - Architecture-sensitive change
   - UI/product-sensitive change
   - Security/compliance-sensitive change
   - Data/financial/integration-sensitive change
   - Production/release/deploy work
2. Apply the matching gate sequence:
   - Context: project instructions, restored context, project memory, project detection
   - Planning: `spec`, `office-hours`, `autoplan`, `plan-eng-review`,
     `plan-ceo-review`, `plan-design-review`, `plan-devex-review`
   - Safety: `guard`, `freeze`, `careful`
   - Build: scoped implementation using existing architecture
   - Quality: `health`, `review`, `investigate`, focused tests
   - Security/compliance: `cso`, secret scan, auth/RBAC/data/public-boundary review
   - Product/UI/QA: `design-review`, `design-consultation`, `qa`, `qa-only`,
     `browse`, `benchmark`
   - Release: `ship`, `land-and-deploy`, `canary` only when explicitly requested
   - Handoff: `context-save`, `document-release`, `learn`
3. Return required gates and release blockers from `gstack_plan`.
4. Build a lead-plus-specialists team plan when task risk justifies it.
5. Run policy and preflight checks before substantial implementation.
6. Run safe health/review/security/QA checks.
7. Run release readiness checks only when release/deploy is explicitly requested.
8. Save context for handoff or later continuation.
9. Keep project-specific production/deployment commands outside the MCP unless
   they are explicitly requested, discovered, selected, and allowed by project
   rules.
