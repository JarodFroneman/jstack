# ADR 0039: Node And Bun Remain Optional Provider Runtimes

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Depends on: [ADR 0037](0037-provider-boundary.md)

## Context

JStack core is Python standard-library-only. gstack's browser and several
artifact paths require Bun, Node, Playwright, and third-party packages. Making
that toolchain mandatory would increase installation size, attack surface,
startup cost, and host incompatibility for users who do not need it.

## Decision

Keep JStack's control core standard-library-only. Node, Bun, Playwright, and
similar runtimes may exist only behind optional Provider interfaces with exact
version discovery and bounded invocation. They are never imported by core
startup paths.

Provider discovery is read-only and cannot install, upgrade, or execute a
runtime. Installation is a separate explicit user-authorized action. Missing
or incompatible runtimes return `UNAVAILABLE` or `UNSUPPORTED` while all
non-provider JStack workflows continue normally.

Dependencies must be pinned, integrity-checked, provenance-recorded, and
scanned. Provider startup, memory, time, network, and output budgets are
measured. No silent model or remote-service fallback is allowed.

## Rejected Alternatives

- Add Bun to the base installer: rejected because most JStack work does not
  require it.
- Vendor gstack's complete dependency tree: rejected as disproportionate.
- Pretend native checks are equivalent when runtime is missing: rejected as
  fabricated evidence.

## Consequences

Core remains lightweight and portable. Browser-rich users accept a deliberate
optional setup and clear availability states.
