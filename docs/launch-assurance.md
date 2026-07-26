# JStack Launch Assurance v2

JStack 0.9 upgrades the launch-evidence layer used by all five existing
workflows. It does not add a sixth command. Launch Assurance v2 converts the
reviewed pre-launch checklist into a risk-tiered, target-bound verification
contract that cannot pass from a model-written summary or caller-declared
outcome.

The canonical catalog is `mcp/jstack/launch/catalog.v2.json`. It is generated
deterministically by `catalog_builder.py` and contains exactly 47 controls:
14 security, 5 email, 7 findability, 4 speed, 6 analytics, 5 legal, and 6 final
test controls. The strict registry rejects unknown fields, invalid ordering,
unsupported evidence, weakened risk metadata, and any catalog that differs
from the deterministic v2 contract.

The retained v1 catalog and schemas are migration references only. New
assessments, evidence receipts, and launch receipts use v2.

## Risk and applicability

Every assessment declares `core`, every real surface, and one risk tier:

| Risk tier | Typical scope | Mandatory escalation |
| --- | --- | --- |
| `low` | Internal or contained software without a higher-risk surface | Catalog gate levels apply |
| `medium` | Public web, browser, email, analytics, commercial, or licensed-asset changes | Cannot be declared below a surface floor |
| `high` | Authentication, cookies, databases, tracking, untrusted input, cross-origin APIs, personal data, AI/vendor cost, or other cost-bearing endpoints | Every selected security control is a blocker; an independent scanner is mandatory |
| `critical` | Payments or regulated data | Required controls become blockers, waivers are forbidden, and both independent scanner and independent human security review are mandatory |

The project policy can raise `minimumRiskTier`; it cannot lower a surface
floor. A caller may voluntarily choose a higher tier.

The 22 surfaces are:

- `core`
- `public-web`
- `browser-ui`
- `authenticated`
- `cookie-authenticated`
- `database`
- `transactional-email`
- `search-indexed`
- `performance-sensitive`
- `analytics`
- `payments`
- `commercial`
- `tracking`
- `ai-paid-endpoints`
- `regulated-data`
- `public-form`
- `cross-origin-api`
- `untrusted-input`
- `cost-bearing-endpoints`
- `personal-data`
- `licensed-assets`
- `software-supply-chain`

JStack performs a bounded, content-minimized static scan of tracked code and
configuration. It returns only surface names, confidence, matched paths, and
marker labels—never source content. Every detected surface must either be in
the declaration or have an accountable `not-applicable` reconciliation owned
by the profile owner and linked to an evidence reference. Unresolved hints
produce no launch-session token.

Static detection is a completeness aid, not the owner of business truth. Code
cannot reliably reveal merchant structure, jurisdictions, production topology,
data-processing agreements, or every third-party system. The accountable
surface declaration remains mandatory.

## Protocol

### 1. Assess

`jstack_launch_assess` requires:

- a clean committed Git release candidate and explicit pre-release `base_ref`;
- `core` plus every applicable surface;
- `risk_tier`;
- an immutable lowercase SHA-256 `deployment_fingerprint`;
- target environment and an HTTPS URL when the selected surface requires one;
- accountable profile owner and reference; and
- reconciliations for any detected-but-omitted surface.

The 30-minute session binds Git HEAD, workspace fingerprint, base commit,
policy, tool version, catalog, control selection, risk tier, deployment
fingerprint, surface-hint digest, reconciliation digest, environment, URL, and
profile declaration.

The deployment fingerprint identifies the exact build, image, package,
artifact, or deployment revision examined by runtime evidence. A branch name,
`latest`, mutable URL, or prose label is not a fingerprint.

### 2. Register structured evidence

`jstack_launch_evidence_register` accepts one selected control requirement and
one structured artifact. The artifact must be a bounded regular non-symlink
file inside the Git project or `~/.jstack/evidence`.

Supported formats are:

- `jstack-json`: `jstack.launch.artifact.v2`, containing producer identity,
  exact target, scope, observation time, completeness, truncation, and
  assertion records;
- `scanner-json`: provider-neutral `jstack.scanner.result.v1`; or
- `sarif-2.1.0`: SARIF with the required bounded JStack target, scope,
  ruleset, completeness, truncation, time, and independence metadata.

The caller does not provide `pass`, `fail`, a verifier name, or a summary.
JStack parses the artifact and derives:

- `incomplete` when required assertions are missing or unknown, observation
  floors are unmet, or the producer reports incomplete/truncated coverage;
- `fail` when a required or supplied assertion fails;
- `not-applicable` only when every assertion is explicitly not applicable and
  the control permits it; or
- `pass` only when every required assertion and completeness constraint passes.

Receipts retain hashes and bounded counts, not raw artifact content. They bind
the producer, semantic result, control requirement, Git commit, environment,
deployment fingerprint, catalog, selection, and freshness window. Duplicate
semantic evidence cannot be counted twice.

### 3. Finalize composite controls

`jstack_launch_finalize` evaluates every active requirement independently.
One configuration snapshot cannot satisfy a multi-part control.

Important composite boundaries include:

- database access: effective policy plus anonymous and cross-tenant read/write
  negative probes;
- authentication/authorization: unauthenticated, wrong-role, expired-session,
  entitlement, recovery, replay, and throttling matrices;
- cost exposure: abuse rate limits plus quotas, provider hard caps, spend
  alerts, anomaly ownership, and a tested kill switch;
- browser security: HTTPS, response headers, CORS, CSRF, server input
  validation, and error/data minimization remain separate controls;
- data governance: implementation data map plus accountable legal scope and
  jurisdiction record;
- provenance: software/asset inventory plus license disposition; and
- high/critical security: independent scanner, with an additional independent
  human review at critical risk.

Missing, failed, incomplete, stale, contradictory, or contract-drifted
blocker/required requirements prevent `ready=true`. Advisory gaps remain
warnings.

Catalog blockers cannot be waived. At high and critical risk, security controls
cannot be waived. At critical risk, no control can be waived. An otherwise
eligible waiver requires an owner, reason, external reference, expiry within 30
days, compensating control, and residual risk; project policy can disable
waivers entirely.

The final receipt expires no later than 24 hours, its earliest evidence, or its
earliest waiver. Git, policy, catalog, selection, risk, surface-hint,
reconciliation, environment, deployment, target, or server-session drift
invalidates it.

## Scanner ownership

Scanner parsing belongs to JStack Audit and is provider-neutral. Launch
Assurance consumes only the normalized result. It does not execute a scanner,
upload code, or treat a tool brand as proof.

The parser rejects wrong targets, missing scope, malformed timestamps, unsafe
or unknown fields, excess runs/findings, non-independent evidence when
independence is required, and incomplete or truncated output. Unresolved
critical or high findings fail their assertions. Accepted-risk findings remain
unresolved for this gate; the scanner requirement itself cannot be waived at
high or critical risk.

An independent scan is not equivalent to a penetration test, complete
application-security review, or proof that the ruleset covered every weakness.
Critical systems therefore require a separate independent human security-review
artifact as well.

## Policy

The v2 policy floor is:

```json
{
  "launch": {
    "requireReceiptForProduction": true,
    "requireProfileDeclaration": true,
    "requireSurfaceReconciliation": true,
    "requireDeploymentFingerprint": true,
    "minimumRiskTier": "low",
    "maxEvidenceAgeMinutes": 1440,
    "requiredControlIds": [],
    "advisoryControlIds": [],
    "requireReleaseAuditForSurfaces": [
      "public-web",
      "commercial",
      "payments",
      "regulated-data"
    ],
    "allowWaivers": true
  }
}
```

A repository can strengthen the floor with a higher minimum risk, additional
required controls, shorter evidence age, more release-audit surfaces, or
disabled waivers. It cannot disable production receipts, deployment binding,
surface reconciliation, or the mandatory risk escalations.

## Release, loop, and program integration

Production `jstack_release_readiness` requires a current passing v2 launch
receipt in addition to QA, security, approval reference, rollback, and
monitoring/canary evidence. A valid profile containing `public-web`,
`commercial`, `payments`, or `regulated-data` also requires a complete
repository-wide release-profile audit by default.

Loops and programs can use launch assurance as a typed acceptance criterion:

```json
{
  "id": "launch-ready",
  "description": "The exact production public-web launch profile passes.",
  "verifier": {
    "type": "launch",
    "targetEnvironment": "production",
    "surfaces": ["core", "public-web"]
  }
}
```

Checkpoint and finalization calls revalidate the signature, Git state,
baseline, policy, catalog, applicability selection, risk, deployment
fingerprint, detected hints, reconciliation, environment, and normalized
surface set. A different or narrower target cannot satisfy the criterion.

## Safety and attestation limit

Launch tools make no network request and perform no provider, payment,
deployment, or production action. Real email, DNS, browser, device, analytics,
search-console, legal, payment, runtime, and penetration-test evidence must be
gathered through a separately authorized safe workflow.

Every launch and release result returns `executionAuthorized=false`. A passing
receipt proves that JStack parsed current target-bound evidence and derived
the catalogued assertions. It does not certify producer honesty, facts outside
the observed scope, legal sufficiency, complete vulnerability coverage, or
production behavior not represented by the exact deployment fingerprint.

## Source adaptation

The catalog preserves and paraphrases the relevant concepts from
[Nico Burkart's 37-point pre-launch checklist](https://nicoburkart.notion.site/e6e88fff5ddf48a09248e2c8368445d1?v=3a293082ae3e81d0b778000c94c436d0&p=3a493082ae3e819bb4f0d4e52c1cc446&pm=s)
and the reviewed
[20+ year developer pre-launch article shared on X](https://x.com/PrajwalTomar_/status/2080974596392837123).
The sources inform coverage; JStack's evidence model, risk floors, gate levels,
and safety boundaries are independent engineering decisions. Vendor choices
and jurisdiction-specific legal conclusions remain conditional and
human-owned.
