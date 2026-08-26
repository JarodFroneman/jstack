# Stage 17 — Modularity Refactor

## Status

| Item | Value |
| --- | --- |
| Objective | Extract meaningful seams without creating another monolith |
| Advance gate | **PASS** — new stage logic is cohesive, standard-library only, and independently testable |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

Stage 17 keeps `jstack_mcp_server.py` as the MCP adapter but moves new policy
and contract logic behind four narrow, deterministic packages:

| Seam | Responsibility | Lines |
| --- | --- | ---: |
| `mcp/jstack/orchestration/delivery.py` | Team Plan → delivery/evidence projection | 420 |
| `mcp/jstack/release/choreography.py` | Readiness → release UX projection | 204 |
| `mcp/jstack/providers/security.py` | Security-tool catalog and evidence plan | 181 |
| `mcp/jstack/hosts/registry.py` | Host capability catalog and contract | 196 |

These modules do not import the MCP server, execute subprocesses, inspect a
repository, call a model, persist state, or perform external actions. The
dependency direction is adapter → pure contract module; it never points back
to the adapter. Catalog data and JSON Schemas remain separate from code.

The development-only empirical protocol lives in `unified_os_evals/`, outside
the installed MCP and plugin artifact graph. It cannot become a hidden runtime
authority or inflate the production server.

`tests/test_host_compatibility.py` enforces the module-size ceiling, absence of
MCP-server/subprocess imports, package existence, and common authority-kernel
identifier. Product-boundary and artifact-sync checks enforce a standard-
library core, no vendor SDK, no evaluation harness in installed artifacts, six
commands, 60 canonical tools, and 52 frozen aliases.

This stage intentionally does not split stable legacy code merely to improve a
metric. Future extraction should be driven by a tested contract boundary, not
file-count targets.
