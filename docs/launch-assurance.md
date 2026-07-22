# JStack Launch Assurance

JStack 0.8 adds an applicability-aware product-launch evidence layer to the
five existing workflows. It does not add a sixth command. The launch layer
turns a reviewed 37-item pre-launch checklist into versioned controls that are
selected from declared product surfaces, resolved with typed current evidence,
and consumed by release readiness.

The canonical catalog is
`mcp/jstack/launch/catalog.v1.json`. Its validator rejects unknown fields,
duplicate IDs, missing sequence numbers, invalid surfaces, unsupported evidence
kinds, weakened blocker metadata, and any catalog other than the exact 37-control
v1 shape. The catalog and each applicability selection receive stable SHA-256
digests.

## Applicability profile

Every profile explicitly includes `core`, then any real product surfaces:

| Surface | Activates evidence for |
| --- | --- |
| `public-web` | transport, exposed routes, metadata, crawler behavior, public legal links, and final public-flow checks |
| `browser-ui` | client secrets, responsive interaction, images, layout stability, forms, and browser/device coverage |
| `authenticated` | server-side authentication, authorization, entitlements, and abuse boundaries |
| `database` | row and tenant access boundaries |
| `transactional-email` | SPF/DKIM/DMARC, real email triggers, mailbox delivery, rendering, and sender topology |
| `search-indexed` | sitemap, indexability, metadata, and crawler policy |
| `performance-sensitive` | reproducible page-performance baseline and budget |
| `analytics` | event delivery, web vitals where relevant, funnels, errors, and consent behavior |
| `payments` | merchant ownership, legal alignment, and safe live-webhook evidence |
| `commercial` | customer-facing domain, funnel, disclosure, and release-audit expectations |
| `tracking` | consent, storage, withdrawal, recording, and redaction behavior |
| `ai-paid-endpoints` | server-side cost and abuse rate limits |
| `regulated-data` | accountable privacy/legal evidence and mandatory release audit |

JStack deliberately does not infer the final profile. Source inspection can
suggest surfaces, but an accountable owner must declare them because merchant,
legal, tracking, and operational facts may not be visible in code. Omitting a
known surface to avoid a gate is a failed profile declaration.

The catalog retains the source checklist's category and priority as provenance,
but uses independent JStack gate levels: `blocker`, `required`, or `advisory`.
The distribution is six security, five email, seven findability, four speed,
six analytics, three legal, and six final-test controls.

## Protocol

### 1. Assess

`jstack_launch_assess` requires a clean committed Git candidate, explicit
pre-release `base_ref`, target environment, profile owner and reference, and
the complete surface declaration. Production web-like targets must use a
bounded HTTPS URL with no credentials, query text, or fragment.

The response contains the complete applicable and excluded control set and a
30-minute signed session token bound to:

- Git HEAD, workspace fingerprint, and base commit;
- enterprise policy and JStack version;
- catalog and selection digests;
- surfaces, target environment, and target URL; and
- profile owner and a digest of the external declaration reference.

### 2. Register evidence

`jstack_launch_evidence_register` accepts one artifact and one selected control.
The artifact must be a regular, non-symlink file no larger than 100 MB inside
the repository or `~/.jstack/evidence`. JStack uses stable file-identity hashing
and returns no artifact content.

Each receipt records the control, effective gate, permitted evidence kind,
`pass`, `fail`, `incomplete`, or permitted `not-applicable` outcome, named
verifier, digested source reference and summary, artifact identity, observation
time, and expiry. Evidence is capped by both the catalog and policy freshness
window. Future, already stale, foreign-session, changed-worktree, wrong-control,
or wrong-kind evidence fails closed.

A signed receipt proves what artifact and attestation were registered against
which contract. It does not independently prove that the artifact's semantic
claim is true. The named verifier remains accountable.

### 3. Finalize

`jstack_launch_finalize` validates the session and every evidence receipt
against the current project, policy, catalog, and selection. Duplicate outcomes
are rejected. Missing, failed, incomplete, invalid, or stale blocker/required
evidence prevents `ready=true`; advisory gaps remain warnings.

Blockers cannot be waived. A waivable required control needs an owner, reason,
external approval reference, expiry within 30 days, compensating control, and
residual risk. Projects can disable waivers. A recorded waiver is not a signed
legal or security certification.

The final receipt expires no later than 24 hours, its earliest input evidence,
or its earliest waiver. Any Git, policy, catalog, profile, environment, target,
or server-session change invalidates it.

## Release integration

Production `jstack_release_readiness` now requires a current passing launch
receipt in addition to QA, security, approval, rollback, and monitoring/canary
evidence. A valid profile containing `public-web`, `commercial`, `payments`, or
`regulated-data` also makes the repository-wide release-profile audit receipt
mandatory by default.

The policy section is:

```json
{
  "launch": {
    "requireReceiptForProduction": true,
    "requireProfileDeclaration": true,
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

A repository can strengthen the floor with additional required controls,
shorter evidence age, more audit-triggering surfaces, or disabled waivers. It
cannot disable production receipts, remove the explicit profile, weaken the
default audit surfaces, or waive a blocker.

## Loop and program integration

Loops, program phases, and program final acceptance can make launch assurance a
typed acceptance criterion:

```json
{
  "id": "launch-ready",
  "description": "The exact production public-web profile passes.",
  "verifier": {
    "type": "launch",
    "targetEnvironment": "production",
    "surfaces": ["core", "public-web"]
  }
}
```

Checkpoint and finalization calls accept `launch_receipt`. JStack verifies the
signature and exact Git state, baseline, policy, tool version, catalog,
applicability selection, environment, and normalized surface set. A receipt for
a different environment or even a narrower surface set does not satisfy the
criterion. This makes launch assurance a first-class machine gate without
silently adding it to projects that did not declare a launch boundary.

Because assessment requires a clean committed candidate, this criterion is a
late release/program boundary. It does not grant commit authority or weaken the
external-action protocol.

## Safety and authority

Launch tools make no network request and perform no provider or production
action. They only select controls, hash existing evidence, validate contracts,
and issue session-local receipts. DNS, mailbox, browser, device, analytics,
search-console, legal, and provider evidence must be gathered by a safe,
separately authorized workflow.

In particular, the live-payment control does not authorize a charge, refund,
webhook replay, or production mutation. Any real-money exercise needs explicit
production-mutation authority, bounded value, rollback, reconciliation, and
monitoring. Every launch and release result returns
`executionAuthorized=false`; the v0.7 exact one-action authorization boundary
continues unchanged in v0.8.

## Source adaptation

The catalog adapts concepts from [Nico Burkart's 37-point pre-launch
checklist](https://nicoburkart.notion.site/e6e88fff5ddf48a09248e2c8368445d1?v=3a293082ae3e81d0b778000c94c436d0&p=3a493082ae3e819bb4f0d4e52c1cc446&pm=s),
reviewed on 2026-07-22. JStack paraphrases and conditions the controls instead
of copying vendor prescriptions. Mail-tester scoring, application-domain
separation, session recording, and `llms.txt` remain advisory or conditional;
legal sufficiency remains an accountable human decision.
