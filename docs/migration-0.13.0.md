# Migrating to JStack 0.13.0

JStack `0.13.0` adds `/jstack-cso` as the seventh public workflow. It is a
read-only enterprise application, API, frontend-exposure, authorization,
proprietary-logic, reverse-engineering, and AI-security auditor for projects
the user is authorized to assess.

JStack CSO specializes the existing JStack Audit evidence/finalization kernel
and `chief-security-officer` specialist. It does not add a second security
authority, a new MCP operation, a runtime dependency on GStack, or permission
to remediate, publish, release, deploy, contact discovered systems, or access
production.

The word **stable** identifies the release channel and compatibility target.
It does not certify vulnerability absence, prompt-injection prevention,
reverse-engineering prevention, attack immunity, standards compliance, or
universal production readiness.

## Compatibility preserved

- The existing six commands remain unchanged. `/jstack-cso` is additive.
- The canonical MCP surface remains 65 `jstack_*` tools and the compatibility
  surface remains 52 frozen `gstack_*` aliases.
- Existing Prompt Compiler, Product Interface, Audit, Graphify Project
  Intelligence, Loop, Program, Launch Assurance, QA, security, and release
  boundaries remain intact.
- The JStack runtime core remains Python-standard-library only.
- Existing loop, program, UI, audit, mastery, context, and Project Intelligence
  state requires no migration.

## What changes

- Seven dedicated command plugins now ship at one release version. The optional
  umbrella plugin and transactional direct installer include `jstack-cso`.
- Prompt Compiler accepts `workflow_mode="jstack-cso"`, applies a non-lowerable
  read-only authority floor, and routes context readiness through the existing
  Audit workflow.
- A fixed local collector inventories browser-delivered artifacts, detects and
  redacts recognized secrets, maps API response properties, identifies missing
  authorization signals, reviews proprietary logic placement, assesses AI
  prompt/tool/output boundaries, and reports suspicious scanned instructions
  without obeying them.
- Closed evidence/report schemas and an owner-private report writer support
  optional saved JSON output beneath `.jstack/security-reports/`.
- Exact MIT attribution and immutable GStack source provenance are retained;
  the installed workflow has no GStack runtime dependency.

## Security boundary

Anything delivered to a browser is inspectable. Minification, obfuscation,
disabled browser controls, hidden DOM content, and hidden anti-AI prompts are
not confidentiality controls.

The collector executes no project code, follows no symlinks, and makes no
network request. File, byte, evidence, and output limits fail coverage closed.
Recognized secrets are redacted, and validated reports reject traversal,
overwrite, broad file modes, unknown fields, and unredacted secret patterns.
Manual challenge review remains required because deterministic candidates can
contain false positives and can miss vulnerabilities.

## Before upgrading

1. Record the active JStack version, enabled plugin layout, MCP path,
   marketplace source, configuration hash, tool inventory, and `~/.jstack`
   inventory.
2. Preserve the complete `v0.12.0` installation as one rollback unit,
   including plugin sources, cache, shared MCP, marketplace metadata, Codex
   configuration, and the existing managed Graphify runtime.
3. Preserve all JStack state. Do not remove loops, programs, UI evidence,
   mastery state, Project Intelligence snapshots, or keys.
4. Verify that the checkout is the exact annotated `v0.13.0` tag and resolves
   to the published stable GitHub Release commit.

## Validate the source

From the immutable `v0.13.0` checkout, run:

```bash
python3 scripts/sync_artifacts.py --check
python3 scripts/check_contract_compatibility.py
python3 scripts/check_product_boundaries.py
python3 -m evals.runner.cli verify-lock
python3 -m compileall -q mcp scripts tests evals skills/jstack-cso
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

The release pull request must also pass the complete cross-platform CI matrix
and target-bound CodeQL. JStack CSO does not replace independent release
scanning or accountable human review where policy requires it.

## Install and verify

Use exactly one distribution layout from
[installation.md](installation.md). Preserve the currently managed Project
Intelligence provider by using the same installation option selected for
`v0.12.0`.

After activation, restart Codex or open a fresh task and verify:

- all seven dedicated plugins report `0.13.0` and are enabled;
- the umbrella plugin and duplicate direct command copies are absent;
- the shared MCP initialize response reports `0.13.0`;
- `tools/list` reports 65 canonical tools and 52 frozen aliases;
- `/jstack-cso` appears exactly once and resolves to the packaged JStack CSO
  skill;
- exactly one `product-ui-design` skill remains active through `j-stack-dev`;
- installed plugin, MCP, schema, scanner, and provenance bytes match the
  release; and
- the installed MCP smoke test plus a bounded JStack CSO fixture audit pass.

## State and receipts

The upgrade creates no state migration. Prompt, context, Audit, CSO, graph,
QA, security, UI, release, or other session receipts bound to the replaced
JStack version or server session must be reissued normally.

## Rollback

If activation, startup, inventory, hash, scanner, or smoke verification fails:

1. stop using the `0.13.0` installation;
2. restore the complete preserved `v0.12.0` plugin, cache, MCP, marketplace,
   configuration, and managed-provider unit;
3. preserve current `~/.jstack` state unless corruption is demonstrated;
4. restart Codex; and
5. verify restored `v0.12.0`, the six-command 65/52 tool surface, hashes,
   Graphify lifecycle, and MCP smoke test.

Do not create a mixed installation by restoring individual generated files.

## Further reading

- [JStack Audit and CSO](audit-system.md)
- [Installation](installation.md)
- [Security policy](../SECURITY.md)
- [Complete changelog](../CHANGELOG.md)
