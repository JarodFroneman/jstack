# ADR 0024: Product Interface Reference Evidence Builder

- Status: accepted for implementation
- Target release: 0.10.0-beta.3
- Decision date: 2026-08-19

## Context

The Product Interface System verifies the implemented candidate, but users also
need a safe way to supply screenshots, Figma exports, and approved web pages as
design input before implementation. Treating those inputs as candidate evidence
would collapse source inspiration and verification, while embedding a complete
third-party screenshot-to-code web application would add provider SDKs, network
services, and a second application runtime to JStack's dependency-free core.

## Decision

Add `/jstack-evidence-builder` as a sixth, explicitly invoked preprocessing
workflow. It orchestrates host browser/vision capabilities and two canonical-
only MCP tools:

- `jstack_ui_reference_contract` freezes the clean Git baseline, accepted
  source kinds, viewports, provider boundary, and optional isolated prototype
  mode.
- `jstack_ui_reference_finalize` validates a complete private bundle beneath a
  server-selected `~/.jstack/evidence/ui-reference/...` root and returns only
  normalized digests, counts, classifications, and a signed receipt.

The reference receipt can be supplied to `jstack_ui_contract`. Only its
digest-only binding enters the UI contract and therefore the contract digest.
Contracts without a reference remain byte-compatible
`jstack.ui.contract.v1`; attaching a reference produces the closed additive
`jstack.ui.contract.v2` shape.
`jstack_ui_finalize` remains unchanged in authority: it still requires a clean
descendant candidate, exact QA receipt, current candidate screenshots,
objective results, and structured Product observations. Reference material
never qualifies as candidate evidence.

The v1 bundle accepts metadata-stripped PNG, JPEG, and WebP sources from
user-provided screenshots, Figma exports, or exact user-approved host-browser
captures. Each source records rights basis, sensitive-data treatment, and
external-processing disclosure. Optional prototypes are static standalone
HTML/CSS or HTML/Tailwind, limited to two variants and rendered with network
access disabled. Active content and external resources are rejected.
The contract, bundle manifest, and structured analysis formats each ship as a
closed versioned JSON Schema.

`abi/screenshot-to-code` at commit
`d026163f586dfa8c5c10d28c36edd59a9d3b0e88` is a pinned design reference, not
an embedded runtime. JStack does not vendor its FastAPI/Vite application,
provider clients, prompts, or permissive service configuration.

## Consequences

- The live MCP surface becomes 56 canonical `jstack_*` tools; the frozen 52
  `gstack_*` aliases remain unchanged and no aliases are added.
- The dedicated plugin layout becomes six command plugins. The automatic
  `product-ui-design` implementation skill remains owned by `j-stack-dev`.
- Reference finalization is a provenance/integrity claim only. It is not legal
  permission, semantic truth, accessibility assurance, QA, security evidence,
  release approval, or execution authority.
- URL capture requires an available host browser and explicit URL scope.
  External-provider use is opt-in and disclosed before bytes leave the host.
- Video, Replicate, production framework exporters, and an embedded
  screenshot-to-code service remain deferred.
