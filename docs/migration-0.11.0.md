# Migrating to JStack 0.11.0

JStack `0.11.0` is the stable packaging of the staged Unified Engineering OS
work through Stage 20. It upgrades JStack's internal composition,
methodology, provider, host, Product/Design, delivery, security, provenance,
and release contracts while preserving JStack as the only authority kernel.

The word **stable** identifies the release channel and compatibility target.
It is not a claim that every generated system is production-ready, that all
optional providers are available, or that the combined approach outperforms a
base agent, baseline JStack, or gstack. Stage 19 remains `NOT_MEASURED`; its
168-cell study has not run.

## Compatibility preserved

- Six public commands remain unchanged:
  `/j-stack-dev`, `/jstack-subagents`, `/jstack-full-team`, `/jstack-loop`,
  `/jstack-audit`, and `/jstack-evidence-builder`.
- The MCP surface remains 60 canonical `jstack_*` tools and 52 frozen legacy
  `gstack_*` aliases.
- The installed runtime core remains Python-standard-library only.
- Existing Prompt Compiler, Context Readiness, Product Interface, Audit, Loop,
  Program, Launch Assurance, QA, security, and release receipts retain their
  authority boundaries.
- Omitted additive inputs preserve deterministic legacy behavior. They do not
  silently select a provider, broaden scope, create a team, or authorize an
  external action.

## What changes

- Team Composer can project the existing command-selected staffing model into
  deterministic Solo, Professional, or Enterprise delivery while respecting
  the command's role ceiling and write permissions.
- Original JStack-native methodology, root-cause investigation,
  Product/Design, browser evidence, QA remediation, host/provider, delivery,
  security-tooling, and release-choreography contracts are available through
  the existing workflow and receipt planes.
- gstack is recorded at immutable commit
  `ad8400543cd9ce8d07641362db48d44a95417e33` and tree
  `993294b0a09f5265d2d5af6d2fb8234ae2efe450` as MIT-licensed research and
  optional bounded provider input. It is not an ordinary runtime dependency,
  second router, installer, state store, or permission system.
- GitHub CI actions are pinned to full commits, and a separate CodeQL workflow
  scans Python on release pull requests and the main branch.

## Before upgrading

1. Record the currently active JStack version, plugin layout, MCP path,
   marketplace source, configuration hash, and installed tool inventory.
2. Preserve the complete `v0.10.0-beta.6.2` installation as one rollback unit,
   including plugin source/cache, shared MCP, marketplace metadata, and Codex
   configuration.
3. Preserve `~/.jstack/loops/`, `~/.jstack/programs/`, evidence, keys, mastery,
   and context state. Do not copy or delete individual state directories as a
   version-migration shortcut.
4. Verify that the checkout is the exact annotated `v0.11.0` tag and that the
   tag resolves to the published stable GitHub Release commit.

## Validate the source

From the immutable `v0.11.0` checkout, run:

```bash
python3 scripts/sync_artifacts.py --check
python3 scripts/check_contract_compatibility.py
python3 scripts/check_product_boundaries.py
python3 -m evals.runner.cli verify-lock
python3 -m compileall -q mcp scripts tests evals
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

The release pull request must also have a successful target-bound CodeQL scan
and all required accountable review evidence. Local JStack heuristic scanning
does not replace the independent scanner requirement.

## Install and verify

Use one supported distribution layout from
[installation.md](installation.md). Stage the complete `0.11.0` payload,
validate it, then replace the active plugin and shared MCP as one transaction.
Restart Codex or open a fresh task after activation.

Verify:

- all six dedicated plugins report `0.11.0` and are enabled;
- the shared MCP initialize response reports `0.11.0`;
- `tools/list` reports exactly 60 canonical tools and 52 frozen aliases;
- exactly one `product-ui-design` skill is active through `j-stack-dev`;
- installed plugin and MCP bytes match the release candidate; and
- the installed MCP smoke test passes in a fresh process.

## Rollback

If activation, startup, inventory, hash, or smoke verification fails:

1. stop using the new candidate;
2. restore the complete preserved `v0.10.0-beta.6.2` plugin, cache, MCP,
   marketplace, and configuration unit;
3. preserve current `~/.jstack` state unless a specific incompatibility has
   been demonstrated;
4. restart Codex; and
5. verify the restored Beta.6.2 version, 59/52 tool surface, hashes, and MCP
   smoke test.

Do not create a mixed installation by restoring individual generated files.
Receipts bound to the replaced version, policy, provider, host, schema, or Git
candidate must be reissued.

## Further reading

- [Unified Engineering OS index](integration/gstack/README.md)
- [Architecture and compatibility](integration/gstack/TARGET_ARCHITECTURE.md)
- [Security model](integration/gstack/SECURITY_MODEL.md)
- [Upstream provenance and sync](integration/gstack/UPSTREAM_SYNC.md)
- [Stage 19 evaluation boundary](integration/gstack/EVALUATION_PLAN.md)
- [Complete changelog](../CHANGELOG.md)
