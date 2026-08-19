# Reference Bundle Contract

Keep the bundle beneath the exact `referenceRoot` returned by
`jstack_ui_reference_contract`. Use safe relative paths only.

The manifest is canonical JSON plus one LF and uses
`schemaVersion: jstack.ui.reference-bundle.v1`. It contains:

- the signed `contractSha256`;
- a timezone-aware `createdAt`, `complete: true`, and `truncated: false`;
- one to sixteen source records;
- one canonical JSON analysis artifact;
- zero to two contracted prototypes and one selected prototype id when present;
- `manifestSha256`, computed from the canonical object without that field.

Each artifact descriptor contains exactly `path`, `sha256`, `size`, and
`mediaType`. Source records also bind dimensions, optional contracted viewport,
URL digest/authority, rights basis, sensitive-data treatment, metadata removal,
and per-source external-provider disclosure.

The analysis artifact uses `jstack.ui.reference-analysis.v1` with exactly:
`summary`, `layout`, `colors`, `typography`, `components`, `interactions`,
`responsiveBehavior`, `assetNotes`, and `accessibilityNotes`. Every category is
a bounded string array. Record what is observed; do not invent unavailable
states, interactions, tokens, assets, or accessibility behavior.

Use the packaged `ui-reference-contract.v1.schema.json`,
`ui-reference-bundle.v1.schema.json`, and
`ui-reference-analysis.v1.schema.json` as the public machine-readable
contracts.
Passing the final reference receipt to `jstack_ui_contract` produces a
`jstack.ui.contract.v2` candidate contract. Calls without a reference retain
the existing `jstack.ui.contract.v1` shape.
