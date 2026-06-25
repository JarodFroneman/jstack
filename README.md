# gstack-dev Command

Enterprise Codex workflow command, skill, MCP server, and policy templates for
production-grade software work.

`/gstack-dev` is designed to act like a virtual engineering team:

- one accountable Lead Engineer
- conditional specialists for architecture, investigation, build, review, QA,
  security, release, product/UX, quant/backtest, and documentation
- policy-as-code checks
- preflight gates
- release-readiness gates
- quant/backtest validation gates
- mastery training from beginner to expert

## Included

- `prompts/gstack-dev.md` - Codex custom slash command.
- `skills/gstack-dev/SKILL.md` - full operating workflow and mastery system.
- `mcp/gstack/gstack_mcp_server.py` - local stdio MCP server.
- `mcp/gstack/templates/` - enterprise policy, release, PR, team, and quant templates.
- `examples/gstack.enterprise.json` - starter project policy.
- `scripts/install.py` - cross-platform installer for Codex.
- `scripts/install.ps1` - Windows PowerShell wrapper.

## MCP Tools

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

## Install

From the repo root:

```powershell
python .\scripts\install.py
```

Or on Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

Restart Codex or open a new thread after installing so custom commands and MCP
tools reload.

## Smoke Test

```powershell
python .\mcp\gstack\smoke_test.py
```

Expected:

```text
gstack MCP smoke test passed
```

## Project Policy

Copy this into a project root and customize it:

```text
examples/gstack.enterprise.json
```

The MCP will look for:

- `gstack.enterprise.json`
- `gstack.policy.json`
- `gstack.yml`
- `.gstack/gstack.enterprise.json`
- `.gstack/gstack.yml`

## Operating Standard

Small tasks stay single-agent. Complex tasks use a controlled lead-plus-
specialists model. Specialists are read-only by default. Any editing specialist
must have a disjoint write scope. The Lead Engineer owns final synthesis,
verification, and handoff.

This is intentionally not an uncontrolled swarm executor.
