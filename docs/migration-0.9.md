# Migrating To JStack v0.9.0

JStack v0.9.0 upgrades Launch Assurance from caller-attested per-control
outcomes to risk-tiered, assertion-derived evidence. The five slash commands,
host-native action-safety model, and no-token workflow are unchanged.

## Breaking launch-protocol changes

- `jstack_launch_assess` now requires `risk_tier` and a lowercase SHA-256
  `deployment_fingerprint`.
- Assessment statically detects surface hints. A detected surface must be
  declared or supplied in `surface_reconciliation` as an accountable
  `not-applicable` decision.
- The surface catalog expands from 14 to 22 entries and the control catalog
  from 37 to 47 controls.
- `jstack_launch_evidence_register` now requires `requirement_id` and
  `artifact_format`.
- Registration no longer accepts caller-supplied `outcome`, `verifier`,
  `summary`, or `observed_at`. Observation time and outcome come from the
  structured artifact.
- Launch session, evidence, finalization, and receipt schemas move from v1 to
  v2. Existing v1 launch tokens and receipts cannot satisfy a v0.9 gate.
- One control can require multiple evidence receipts. Finalization accepts up
  to 300 receipts and evaluates each requirement independently.

## Structured artifact conversion

Replace a prose file and caller outcome such as:

```json
{
  "control_id": "security-database-row-access",
  "outcome": "pass",
  "artifact_path": "README.md",
  "verifier": "reviewer"
}
```

with an artifact conforming to
`mcp/jstack/schemas/launch-evidence-artifact.v2.schema.json`:

```json
{
  "schemaVersion": "jstack.launch.artifact.v2",
  "controlId": "security-database-row-access",
  "requirementId": "cross-tenant-probe-matrix",
  "producer": {
    "name": "tenant-boundary-test",
    "version": "1.0.0",
    "independent": false
  },
  "target": {
    "gitHead": "0123456789abcdef0123456789abcdef01234567",
    "targetEnvironment": "production",
    "deploymentFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "scope": ["tenant-api"]
  },
  "observedAt": "2026-07-26T12:00:00+00:00",
  "complete": true,
  "truncated": false,
  "assertions": [
    {"id": "anonymous-read-denied", "status": "pass", "observations": 1},
    {"id": "anonymous-write-denied", "status": "pass", "observations": 1},
    {"id": "cross-tenant-read-denied", "status": "pass", "observations": 1},
    {"id": "cross-tenant-write-denied", "status": "pass", "observations": 1}
  ]
}
```

The exact assertion IDs and permitted formats are returned under each
`activeEvidenceRequirements` entry in the assessment selection.

## Scanner integration

At high risk, provide an independent `scanner-json` or SARIF 2.1.0 artifact for
`security-final-independent-scan/independent-security-scan`. Critical risk also
requires `critical-human-security-review` as a separate independent
`jstack-json` artifact.

Use:

- `mcp/jstack/schemas/external-scanner-result.v1.schema.json` for the
  provider-neutral scanner format;
- `mcp/jstack/schemas/launch-evidence-artifact.v2.schema.json` for native
  control evidence; and
- `mcp/jstack/schemas/launch-evidence.v2.schema.json` and
  `launch-result.v2.schema.json` for receipt consumers.

Incomplete or truncated scans, wrong deployment targets, non-independent
producers, and unresolved high/critical findings do not pass.

## Policy migration

Add the new fields to `launch`:

```json
{
  "requireSurfaceReconciliation": true,
  "requireDeploymentFingerprint": true,
  "minimumRiskTier": "low"
}
```

JStack enforces those floors even when an older valid policy omits them.
Repositories can raise `minimumRiskTier`, but cannot disable target binding or
surface reconciliation.

## Rollback

Rolling back the installed code to v0.8.2 restores the v1 launch protocol, but
v2 session/evidence/final receipts are not compatible with that runtime.
Retain the original evidence artifacts and rerun assessment and registration
with the active version. Never translate a derived v2 result into a
caller-written v1 `pass`.
