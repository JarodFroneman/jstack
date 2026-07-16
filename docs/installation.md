# Installing JStack

JStack supports two installation layouts. Choose one command-distribution
layout and do not combine them.

## Requirements

- Codex Desktop or Codex CLI with MCP support
- Python 3.9 or newer
- Git for commit-bound workflows
- A local clone of this repository

```bash
git clone https://github.com/JarodFroneman/jstack.git
cd jstack
```

Validate the source before installation:

```bash
python3 scripts/sync_artifacts.py --check
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

Use `python` instead of `python3` where required on Windows.

## Layout A: Transactional Direct Install

This is the shortest path for an individual installation. It installs the
canonical prompts, skills, mastery curricula, shared MCP server, and MCP
configuration under `CODEX_HOME`.

macOS and Linux:

```bash
python3 scripts/install.py
```

Windows PowerShell:

```powershell
.\scripts\install.ps1
```

Use a custom Codex home when validating or packaging:

```bash
python3 scripts/install.py --codex-home /absolute/path/to/codex-home
```

The installer stages the complete payload before activation. A late failure
restores every affected target. The previous Codex configuration is retained
as a backup after a successful installation.

## Layout B: Dedicated Command Plugins

This layout provides five clean command surfaces:

- `j-stack-dev`
- `jstack-subagents`
- `jstack-full-team`
- `jstack-audit`
- `jstack-loop`

The dedicated plugins under `plugins/` are skill-only. They require one shared
`jstack` MCP server configured separately.

### 1. Register A Local Marketplace

Register the five directories under `plugins/` in a local Codex marketplace.
Each marketplace source must resolve to the corresponding plugin directory in
this clone. Then install:

```text
codex plugin add j-stack-dev@personal
codex plugin add jstack-subagents@personal
codex plugin add jstack-full-team@personal
codex plugin add jstack-audit@personal
codex plugin add jstack-loop@personal
```

Replace `personal` with the configured marketplace name when using a different
local marketplace.

### 2. Install The Shared MCP Server

Copy `mcp/jstack/` to a stable path outside the Git checkout, for example:

```text
~/.codex/mcp/jstack/
```

Add one server block to `~/.codex/config.toml`, using absolute paths:

```toml
[mcp_servers.jstack]
command = "/absolute/path/to/python3"
args = ["/absolute/path/to/.codex/mcp/jstack/jstack_mcp_server.py"]
startup_timeout_sec = 30.0
tool_timeout_sec = 300.0
```

Do not configure the MCP from both the shared installation and the umbrella
plugin.

### 3. Keep The Umbrella Plugin Uninstalled

The `plugin/` directory is an alternative all-in-one distribution. Installing
it alongside the five dedicated plugins creates duplicate command surfaces.
Use either:

- the five dedicated plugins plus one shared MCP server; or
- the umbrella plugin by itself.

## Verify The Installation

Restart Codex or open a new task after changing plugins or MCP configuration.

Verify the shared server directly:

```bash
python3 ~/.codex/mcp/jstack/smoke_test.py
```

Verify installed plugins:

```text
codex plugin list --marketplace personal
```

Expected dedicated layout:

- all five dedicated plugins are installed and enabled;
- all five report the same release and cachebuster version;
- `jstack@personal` is not installed;
- the MCP initialize response reports the expected JStack release;
- `tools/list` includes the expected `jstack_*` inventory.

## Upgrade

1. Pull or check out the intended immutable release tag.
2. Back up the current MCP directory, plugin sources, installed caches,
   `config.toml`, marketplace configuration, and `~/.jstack` state.
3. Run the complete source validation suite.
4. Stage and validate the new plugin and MCP payload.
5. Replace the shared MCP and reinstall the selected plugin layout.
6. Restart Codex and verify the installed version, tool inventory, hashes, and
   JSON-RPC smoke test.

Do not delete `~/.jstack/loops/`, `~/.jstack/programs/`, or mastery state during
a routine upgrade.

## Rollback

Restore the backed-up plugin sources, installed plugin version, MCP directory,
and Codex configuration as one release unit. Preserve current `~/.jstack` state
unless the target release explicitly documents an incompatible migration.

After rollback, restart Codex and rerun the installed MCP smoke test before
resuming work.

## Troubleshooting

### Commands Appear Twice

Confirm that the umbrella plugin and legacy direct prompt or skill artifacts
are not active alongside the five dedicated plugins. Keep one distribution
layout only, then restart Codex.

### MCP Tools Are Missing

Check the absolute Python and server paths in `config.toml`, run
`smoke_test.py` directly, and open a new Codex task. A successful plugin install
does not configure the shared MCP for skill-only dedicated plugins.

### Git-Required Tools Fail Closed

Run JStack from a valid Git worktree for commit-bound QA, security, audit, and
release receipts. Non-Git directories can use artifact-only planning but do not
receive commit-bound release evidence.
