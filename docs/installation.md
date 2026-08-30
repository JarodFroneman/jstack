# Installing JStack

JStack ships a fully packaged Codex experience and a Claude Code MCP preview.
Choose one Codex command-distribution layout and do not combine those layouts.

## Requirements

- Python 3.9 or newer
- Python 3.10 or newer when installing the optional managed Graphify runtime
- Git for commit-bound workflows
- A local clone of this repository
- Codex Desktop or Codex CLI for full command and continuation support, or
  Claude Code for the MCP preview

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

> **v0.12.0 stable release boundary:** install `v0.12.0` only from its exact
> immutable annotated GitHub release tag, retain the complete
> `v0.11.0` installation as one rollback unit, and verify the installed
> bytes and tool surface. The
> Beta.1 Proof Plane remains byte-frozen to `v0.10.0-beta.1`, uninstalled, and
> unvalidated. Stage 19 also remains `NOT_MEASURED`; its 168-cell comparative
> study has not run. Installing v0.12.0 does not satisfy either deferred study
> or any project-specific independent review. Receipts validate bounded
> contracts and declared evidence only; they do not certify prompt-quality
> uplift, producer honesty, graph completeness, semantic correctness,
> aesthetic quality, attack immunity, or universal production readiness.

## Host Support

| Host | Support level | Boundary |
| --- | --- | --- |
| Codex Desktop and Codex CLI | Full | Release-tested plugins, prompts, skills, MCP tools, and native Goal composition |
| Claude Code | MCP preview | Complete MCP tool inventory over local stdio; no Claude-native command package or automatic equivalent of Codex Goal continuation yet |
| Other MCP clients | Protocol-level | Manual connection may work, but JStack does not claim release-tested host compatibility |

The MCP server is portable. Command discovery, permissions, subagent behavior,
and continuation are host responsibilities, so MCP connectivity alone is not
presented as complete workflow parity.

## Prompt Compiler mode

v0.12.0 defaults `JSTACK_PROMPT_COMPILER_MODE` to `enforced`. The other accepted
values are `shadow`, `preview`, and `disabled`; use `disabled` only as a bounded
compatibility rollback while investigating an integration issue. Mode changes
invalidate existing readiness and compilation receipts. The six packaged
commands perform Stage A before repository inspection and Stage B after
read-only grounding. A context-ready Stage B preview must be shown in full and
explicitly approved before the MCP issues planning receipts. Receipt and prompt
digest binding is MCP-enforced; actual conversational display and human
approval depend on host workflow compliance. JStack cannot intercept arbitrary
native host actions that bypass its commands and MCP tools. See
[Prompt Compiler](prompt-compiler.md) for the exact boundary.

## Codex Layout A: Transactional Direct Install

This is the shortest path for an individual installation. It installs the
canonical prompts, skills, mastery curricula, shared MCP server, and MCP
configuration under `CODEX_HOME`.

macOS and Linux:

```bash
python3 scripts/install.py
```

The direct installer adds one `product-ui-design` skill. Its skill description
automatically routes user-facing interface work; it remains inactive for
backend-only or non-interface work. By default the installer does not edit
global instructions. To also install or refresh the bounded JStack Product UI
block in `CODEX_HOME/AGENTS.md`, explicitly opt in:

```bash
python3 scripts/install.py --manage-agents
```

The managed update preserves content outside its markers, newline style, and
existing POSIX mode and ownership (plus the Windows security descriptor where
applicable), rejects unsafe/malformed targets, and rolls back with the rest of
the install if a later phase fails. It grants no new tool, filesystem, network,
release, deployment, or production authority.

Windows PowerShell:

```powershell
.\scripts\install.ps1
.\scripts\install.ps1 -CodexHome C:\Users\you\.codex -ManageAgents
```

On Windows, the installer runs no-profile PowerShell ACL checks before any
installation mutation, accepts only a `CODEX_HOME` ancestry whose owner and
allow rules are limited to the current user, LocalSystem, and built-in
administrators, and copies each existing config, backup, prompt, or managed
`AGENTS.md` security descriptor to its staged replacement. This applies whether
or not that Python version exposes descriptor-mode operations. An unverifiable,
broad, or reparse-point home fails closed, and custom `CODEX_HOME` paths must
remain beneath the verified current-user profile. The PowerShell wrapper
forwards only `-CodexHome` and `-ManageAgents` and returns the Python installer's
nonzero exit status unchanged. The same owner/DACL boundary is rechecked on
every existing managed descendant, archive and recovery parent, and staged tree
root; recovery data therefore remains beneath the verified private profile.

The umbrella `plugin/` layout launches through Node.js and is tested with
Node.js 22. The dedicated Layout B plugins invoke the Python MCP server directly
and do not add a Node.js runtime requirement.

Use a custom Codex home when validating or packaging:

```bash
python3 scripts/install.py --codex-home /absolute/path/to/codex-home
```

The installer stages the complete payload before activation. A late failure
restores every unaffected target by moving its exact retained preimage back
without replacing a concurrent winner. Replaced installer postimages remain in
a private `CODEX_HOME/jstack-backups/install-preimages-<id>/` recovery set on a
failed activation so an open-descriptor edit cannot be silently discarded.
After a successful upgrade, the exact displaced preimages are retained as the
single bounded `CODEX_HOME/jstack-backups/install-preimages-latest/` recovery
set. JStack never deletes or rotates that set automatically because another
process may still hold a writable descriptor to a displaced file. Verify and
archive or remove it explicitly before the next upgrade; until then, a new
install fails before mutation. Conflict sets are never pruned automatically.
The previous Codex configuration is also retained as
`config.toml.jstack-backup`.

Recovery activation requires same-filesystem atomic no-replace renames beneath
`CODEX_HOME`: Linux uses `renameat2` (the libc wrapper or the supported kernel
syscall), macOS uses `renamex_np(RENAME_EXCL)`, and Windows uses its
destination-must-be-absent rename semantics. An unsupported POSIX platform or
filesystem fails closed. Recovery roots are mode `0700` on POSIX and are
owner/DACL-validated beneath the current-user profile on Windows.

To restore manually, first stop Codex and every process that may still hold a
JStack file open, then archive the current target. Move the numbered recovery
entry back to the matching target only while that target is absent:
`prompt-<name>` maps to `prompts/<name>`; `jstack-dev-skill`,
`jstack-audit-skill`, `jstack-loop-skill`, `product-ui-design`, and
`jstack-mcp` map to their same-named installed skill or MCP directories;
`config.toml`, `config-backup`, and `AGENTS.md` map to the corresponding
`CODEX_HOME` files. Preserve the recovery set if any mapping or live state is
uncertain.

Layout A deliberately refuses to rewrite a valid `config.toml` when its
conservative lexical remover cannot prove a lossless MCP-only edit. That
includes TOML multiline basic or literal strings (and any single-line value
containing a triple-quote delimiter token), plus a root inline
`mcp_servers = { ... }` table. The file is left byte-for-byte unchanged. Use
Layout B and add the documented MCP block manually, or first make a separate
backup and convert those values to ordinary single-line tables/values before
rerunning Layout A.

### Optional Graphify Project Intelligence runtime

JStack's Project Intelligence protocol is built into the existing workflows,
not installed as a skill or seventh command. Its external local-AST provider is
deliberately opt-in so the ordinary installer does not download Graphify or its
dependencies:

```bash
python3 scripts/install.py --with-project-intelligence
```

`--install-graphify` is an equivalent compatibility spelling. To validate a
separate private JStack home, add `--jstack-home /absolute/private/path`.
Project graphs and the runtime do not live under `CODEX_HOME`; their defaults
are `~/.jstack/project-intelligence/` and
`~/.jstack/tools/graphify/0.9.52/` respectively.

The installer accepts only the pinned `graphifyy==0.9.52` catalog entry,
downloads its exact Python Package Index wheel URL, verifies SHA-256 before
installation, creates an isolated virtual environment, and verifies the exact
CLI version. It reuses an existing runtime only when its private marker and
executable match the catalog. A partial, altered, linked, broadly accessible,
or duplicate runtime fails closed. If JStack activation later fails, a runtime
created by that invocation is removed; a verified pre-existing runtime is
preserved.

The Graphify executable is local process code, not part of JStack's Python
standard-library core. JStack runs only local AST extraction and native static
HTML export with a scrubbed environment and no forwarded host API or proxy
credentials. This is process hardening rather than an OS network sandbox. The
top-level wheel is hash pinned; transitive binary dependencies are resolved at
provisioning time and are not yet covered by a complete cross-platform hash
lock. Use a container, VM, or hardened host for untrusted repositories or
provider execution.

The direct installer does not invoke Graphify's own install command and does
not create assistant skills, repository instructions, Git hooks, listeners,
hosted integrations, semantic API clients, or HTTP MCP services. See
[Graphify-backed Project Intelligence](project-intelligence.md) for the
runtime and evidence boundary.

## Codex Layout B: Dedicated Command Plugins

This layout provides six clean command surfaces:

- `j-stack-dev`
- `jstack-subagents`
- `jstack-full-team`
- `jstack-audit`
- `jstack-loop`
- `jstack-evidence-builder`

The dedicated plugins under `plugins/` are skill-only. They require one shared
`jstack` MCP server configured separately. The `j-stack-dev` plugin also owns
the single active `product-ui-design` skill used across UI-scoped JStack work.
That automatic implementation skill is separate from the explicitly invoked
Evidence Builder preprocessing command.

### 1. Register A Local Marketplace

Register the six directories under `plugins/` in a local Codex marketplace.
Each marketplace source must resolve to the corresponding plugin directory in
this clone. Then install:

```text
codex plugin add j-stack-dev@personal
codex plugin add jstack-subagents@personal
codex plugin add jstack-full-team@personal
codex plugin add jstack-audit@personal
codex plugin add jstack-loop@personal
codex plugin add jstack-evidence-builder@personal
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
tool_timeout_sec = 1900.0
```

The 1,900-second transport window covers JStack's longest permitted 1,800-second
capture plus bounded teardown and receipt serialization. Individual command
budgets remain independently bounded by each workflow contract.

Do not configure the MCP from both the shared installation and the umbrella
plugin.

### Optional Stage 6 OSV advisory evidence

Cross-ecosystem Audit Stage 6 evidence can use the curated
`osv-scanner-offline` adapter. Install OSV-Scanner separately, prepare its
local advisory database before the audit, and expose the database directory to
the JStack MCP process as `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. The directory
must exist, be readable, and live outside the audited repository. Restart the
host after changing the MCP environment.

JStack invokes only the fixed offline scan command and never downloads or
updates the database. If the executable or database is absent, the adapter is
reported unavailable and Stage 6 fails closed rather than silently weakening
advisory coverage.

### Stage 7 adversarial-capture isolation

`jstack_adversarial_capture` runs only a discovered command at an exact
reviewed Git state with a scrubbed environment, isolated HOME, closed stdin,
timeouts, and bounded structured output. This local profile is not an OS or
network sandbox and retains the current user's filesystem and network
privileges. Run untrusted repositories or active security tests inside an
externally enforced container or VM with target authorization and appropriate
egress controls. The capture value `none-observed` records an observation; it
does not prove network isolation.

### Stage 8 enterprise audit evidence

Stage 8 consumes the current release-audit, QA, and security receipts directly
between JStack tools. It writes only `audit-report.md`, `audit-result.json`,
`audit.sarif`, and `risk-register.json` beneath `.jstack-training/`; no user
approval token, signing command, challenge, digest, or terminal paste is part
of the workflow. Audit remains read-only and does not implement controls,
accept risk, commit, publish, release, deploy, or access production.

### 3. Keep The Umbrella Plugin Uninstalled

The `plugin/` directory is an alternative all-in-one distribution. Installing
it alongside the six dedicated plugins creates duplicate command surfaces.
Use either:

- the six dedicated plugins plus one shared MCP server; or
- the umbrella plugin by itself.

Do not add a direct `CODEX_HOME/skills/product-ui-design` copy while either the
dedicated `j-stack-dev` plugin or the umbrella plugin is enabled. Exactly one
active copy prevents ambiguous routing. The Python direct installer detects an
enabled plugin copy and fails before mutation rather than creating a duplicate.

## Product Interface Activation And Evidence

For user-facing interface scope, JStack resolves design guidance in this
order: explicit user instruction, the repository's existing design system,
the applicable domain profile, then the `editorial-calm` fallback. Creative,
spatial, media, timeline, or node-based work uses `creative-canvas`; hybrid
products keep `editorial-calm` for the shell and `creative-canvas` for the
workspace. Greenfield UI covers light and dark themes. Existing projects keep
their established supported themes unless the user explicitly requests a
redesign.

The system is an original design framework influenced by calm, hierarchy-led
editorial interfaces and focused creative tools, including qualities users
associate with Claude and Fable. It does not copy proprietary themes, layouts,
assets, branding, or source code, and implies no affiliation or endorsement.

Before implementation, `/jstack-evidence-builder` can collect approved
screenshots, Figma exports, or exact host-browser URL captures beneath a
separate private `~/.jstack/evidence/ui-reference/` root. Its
`jstack_ui_reference_contract` and `jstack_ui_reference_finalize` lifecycle
returns a digest-only reference receipt that can inform `jstack_ui_contract`.
It never satisfies the candidate screenshot matrix, QA, accessibility,
security, launch, release, or deployment evidence. The public file formats are
`ui-reference-contract.v1.schema.json`,
`ui-reference-bundle.v1.schema.json`, and
`ui-reference-analysis.v1.schema.json`. An ordinary candidate contract remains
`ui-contract.v1`; binding a finalized reference emits the additive
`ui-contract.v2` contract.

Evidence Builder contract planning is portable, but Beta.3 reference
finalization requires a supported POSIX host. It fails closed on Windows before
reading the bundle because the stdlib-only server cannot verify inherited DACL
and reparse privacy for the reference root and files.

The Git-only lifecycle uses `jstack_ui_contract` before implementation and
`jstack_ui_finalize` after the clean committed candidate and exact-build QA
receipt exist. The finalizer reads a server-selected private root under
`~/.jstack/evidence/ui/`, validates a complete PNG capture matrix and objective
platform checks, binds build/runtime digests and Product Designer observations,
and issues evidence only. A UI receipt never replaces QA, security, audit,
launch, release approval, or explicit deployment scope. Artifact-only projects
may use the design skill and planning guidance but cannot receive these
commit-bound receipts.

On POSIX hosts, first contract creation also creates one current-user private
`~/.jstack/keys/ui-contract-hmac-v1` key (0700 parent, 0600 single-link file).
It keeps the self-contained contract verifiable across MCP restarts; it does
not make QA, finalization, audit, launch, or release receipts durable. Include
the key in the normal `~/.jstack` backup and never print or copy its bytes into
a repository. Windows keeps UI contracts session-local in Beta.2 rather than
persisting a key whose DACL/reparse ancestry the stdlib-only server cannot
verify. For the same reason, Windows can use automatic routing and contract
planning but `jstack_ui_finalize` fails closed there in Beta.2: the server
cannot prove screenshot and manifest privacy against inherited ACLs and
reparse points. The complete root-bound UI lifecycle must begin and finish on
a supported POSIX host. POSIX privacy checks bind the current UID, regular-file
shape, link count, and mode bits; Beta.2 does not inspect macOS/NFSv4 extended
ACL grants. A POSIX account or evidence/key root shared through an extended ACL
is outside the supported privacy boundary and must not be used for UI
finalization.

Adapter status in Beta.2 is intentionally explicit:

| Adapter | Maturity |
| --- | --- |
| Web | Qualified evidence contract |
| Webview, Electron, Tauri | Contract-only until host or packaged-shell provenance evidence exists |
| iOS, Android, React Native, Flutter, macOS, Windows, Linux | Contract-only until exact target-runtime evidence exists |

Screenshots bind validated bytes, dimensions, coverage, and declared checks;
they do not independently prove capture honesty, runtime provenance, visual
quality, or user preference. Human aesthetic approval is optional and external
to the v1 producer manifest, which cannot authenticate, fabricate, or infer it.

## Claude Code MCP Preview

[Claude Code supports local stdio MCP servers](https://docs.anthropic.com/en/docs/claude-code/mcp),
so it can connect directly to JStack's JSONL server. Use absolute paths for
both Python and the server:

```bash
claude mcp add jstack --scope user -- \
  /absolute/path/to/python3 \
  /absolute/path/to/jstack/mcp/jstack/jstack_mcp_server.py
```

Verify the registration:

```bash
claude mcp get jstack
```

Then open Claude Code, run `/mcp`, and confirm that the `jstack_*` tools are
available. Start with `jstack_runtime_status` and `jstack_detect_project`.

This preview exposes the control-plane tools, but it does not install JStack's
six Codex command plugins. The current loop skill also composes continuation
with Codex Goal mode; Claude operators must supervise continuation manually
until a Claude-native adapter and its release tests ship. Do not interpret MCP
connectivity as unattended execution or full host parity.

## Verify The Installation

Restart the selected host or open a new task after changing plugins or MCP
configuration.

Verify the shared server directly:

```bash
python3 ~/.codex/mcp/jstack/smoke_test.py
```

Verify installed Codex plugins:

```text
codex plugin list --marketplace personal
```

Expected dedicated layout:

- all six dedicated plugins are installed and enabled;
- all six report the same release and cachebuster version;
- `jstack@personal` is not installed;
- exactly one active `product-ui-design` skill is present through
  `j-stack-dev`, with no duplicate direct or umbrella copy;
- the MCP initialize response reports the checked-out release (for this
  release, `0.12.0`);
- `tools/list` includes 65 canonical `jstack_*` tools, including the
  canonical-only `jstack_prompt_compile`, `jstack_context_readiness`,
  `jstack_performance_capture`, and
  `jstack_adversarial_capture`, plus the reference lifecycle
  `jstack_ui_reference_contract` / `jstack_ui_reference_finalize` and candidate
  lifecycle `jstack_ui_contract` / `jstack_ui_finalize`, and motion lifecycle
  `jstack_ui_motion_spec` / `jstack_ui_motion_finalize`, plus
  `jstack_graph_index`, `jstack_graph_query`, `jstack_graph_impact`,
  `jstack_graph_refresh`, and `jstack_graph_finalize`; the frozen
  compatibility surface remains 52 legacy `gstack_*` aliases and has no UI
  or project-intelligence aliases.

## Upgrade

1. Pull or check out the intended immutable release tag.
2. Back up the current MCP directory, plugin sources, installed caches,
   `config.toml`, marketplace configuration, and `~/.jstack` state.
3. Run the complete source validation suite.
4. Stage and validate the new plugin and MCP payload.
5. Replace the shared MCP and reinstall the selected plugin layout.
6. Restart Codex and verify the installed version, tool inventory, hashes, and
   JSON-RPC smoke test.

For `v0.12.0`, also confirm that GitHub marks the release as stable and that the
checked-out annotated tag resolves to the release commit before staging any
global files. The rollback snapshot must contain the actual published
`v0.11.0` installation as one coherent MCP, plugin-source,
plugin-cache, marketplace, and configuration unit.

Do not delete `~/.jstack/loops/`, `~/.jstack/programs/`, or mastery state
during a routine upgrade. An upgrade from v0.8.1 or earlier may leave the retired
`~/.jstack/external-actions/` directory untouched so rollback remains
possible; the current runtime never reads it.

## Rollback

Restore the backed-up plugin sources, installed plugin version, MCP directory,
and Codex configuration as one release unit. Preserve current `~/.jstack` state
unless the target release explicitly documents an incompatible migration.

After rollback, restart Codex and rerun the installed MCP smoke test before
resuming work.

Current JStack releases need no action-identity configuration, signing key, challenge
file, approval token, mailbox response, or terminal approval command. Remove
retired `JSTACK_EXTERNAL_ACTION_*` and `JSTACK_PROGRAM_IDENTITY_CONFIG`
environment settings from the MCP launcher after confirming the upgrade.

## Troubleshooting

### Commands Appear Twice

Confirm that the umbrella plugin and legacy direct prompt or skill artifacts
are not active alongside the six dedicated plugins. Keep one distribution
layout only, then restart Codex.

### MCP Tools Are Missing

Check the absolute Python and server paths in `config.toml`, run
`smoke_test.py` directly, and open a new Codex task. A successful plugin install
does not configure the shared MCP for skill-only dedicated plugins.

### Git-Required Tools Fail Closed

Run JStack from a valid Git worktree for commit-bound QA, security, audit, and
release receipts. Non-Git directories can use artifact-only planning but do not
receive commit-bound release evidence.
