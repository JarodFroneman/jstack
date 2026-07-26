# Launch Assurance

Use Launch Assurance v2 for a clean, committed release candidate. It adds a
risk-tiered product-launch gate to QA, security, audit, rollback, and
monitoring; it does not replace any of them.

## Assess exact applicability

Call `jstack_launch_assess` with:

- explicit `base_ref`;
- `core` plus every applicable surface returned by the active catalog;
- `risk_tier`;
- immutable lowercase SHA-256 `deployment_fingerprint`;
- target environment and URL where required;
- accountable profile owner and reference; and
- `surface_reconciliation` for every detected-but-omitted hint.

Surface and project-policy risk floors cannot be lowered. Static detection is a
completeness aid, not authority over business/legal facts. An unresolved hint
returns no session token. Production web-like targets require bounded HTTPS
URLs without credentials, query text, or fragments.

## Register every structured requirement

Read `selection.selectedControls[].activeEvidenceRequirements`. For each
blocker and required control, register every active requirement using its exact:

- `requirement_id`;
- permitted `evidence_kind`;
- permitted `artifact_format`; and
- assertion and observation contract.

Supported artifacts are native `jstack.launch.artifact.v2`, provider-neutral
`jstack.scanner.result.v1`, or SARIF 2.1.0 with required JStack metadata. Keep
them inside the project or `~/.jstack/evidence`. Never use a README, prose
summary, arbitrary file, raw secret, personal/payment data, mailbox credential,
prompt, session token, or unredacted telemetry as evidence.

Do not provide an outcome, verifier, summary, or observation time in the tool
call. JStack reads the artifact and derives `pass`, `fail`, `incomplete`, or
permitted `not-applicable` from exact target binding, required assertions,
observations, completeness, truncation, and producer constraints.

## Finalize fail-closed

Call `jstack_launch_finalize` with all current evidence receipts. One artifact
does not satisfy multiple requirements unless the catalog explicitly models it
that way. Missing, failed, incomplete, malformed, stale, duplicate,
contradictory, truncated, or contract-drifted blocker/required evidence blocks
readiness.

High risk promotes all selected security controls to blockers and requires an
independent external scan. Critical risk promotes required controls to
blockers, requires both independent scanner and independent human
security-review evidence, and forbids all waivers. High/critical security
controls cannot be waived. Other eligible waivers require owner, reason,
external reference, bounded expiry, compensating control, and residual risk.

## Consume at release readiness

Production `jstack_release_readiness` requires the current passing v2
`launchReceipt`. Public-web, commercial, payments, and regulated-data profiles
also require a current complete repository-wide release-profile audit by
default.

Launch tools perform no web requests, payments, deployments, or production
mutations. They parse and bind evidence only. Every launch and release result
has `executionAuthorized=false`.

The active 47-control v2 catalog adapts the reviewed pre-launch sources into
provider-neutral engineering controls. JStack's risk floors, evidence model,
and gates are independent judgments; legal sufficiency, producer honesty, and
facts outside observed scope remain human-owned uncertainty.
