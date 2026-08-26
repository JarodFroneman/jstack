# JStack Provider Model

## Purpose and boundary

A Provider is an optional, bounded runtime adapter that may perform declared
work or produce candidate-bound evidence after JStack validates the request and
the user/host authorizes the applicable effect. A provider is never a router,
policy engine, canonical role, specialist, evidence verifier, or action
authority.

The formal provider concept is defined in
`mcp/jstack/schemas/unified-os-domain.v1.schema.json#Provider`. Provider-
specific contracts live under `mcp/jstack/providers/` and
`mcp/jstack/schemas/`.

## Fixed invariants

Every provider boundary preserves:

```text
orchestrator = false
canSelfAuthorize = false
authorityEffect = none
crossProjectAllowed = false
rawContentAllowed = false
silentEgressAllowed = false
```

Declared effects describe a technical maximum after authorization; they do
not grant the effect. A provider result is untrusted input and does not become
evidence merely because the process exited successfully.

## Lifecycle

```text
read-only discovery
  → availability and host-capability report
  → closed provider request
  → exact effect/authority check
  → bounded invocation, when separately authorized
  → closed untrusted result
  → schema/path/digest/size/freshness verification
  → project/repository/candidate/provider/host binding
  → domain evidence verification
  → non-authorizing receipt
```

Discovery never installs, upgrades, logs in, downloads a browser, starts a
tunnel, sends source to a vendor, or executes a project. Invocation may occur
only for a provider kind that the installed JStack version and current host
contract support.

## Current surfaces

| Surface | Current candidate behavior | Not provided |
| --- | --- | --- |
| Browser evidence | Canonical-only `jstack_browser_capture` can select one explicitly approved local `package.json` browser script and normalize digest-only evidence | Vendored gstack browser, raw CDP, tunnels, cookie import, source remediation, or deployment |
| Security tooling | Provider-neutral catalog selects active or optional evidence controls by risk | Scanner installation, vendor submission, raw-result storage, or proof of no vulnerabilities |
| Host contracts | Codex is full, Claude Code is preview, generic MCP is protocol-only, and unknown hosts are unsupported | Emulated host features or semantic parity inferred from MCP connectivity |
| Release choreography | Direct, canary, and blue-green readiness presentation | Deployment provider or production execution |

The pinned gstack browser, model, artifact, scraper, canary, setup, and device
surfaces remain research candidates unless a later JStack-native contract and
verification stage explicitly implements them. No upstream runtime is selected
by name merely because gstack is installed.

## Availability and fallback

Providers report normalized availability such as `AVAILABLE`, `UNAVAILABLE`,
or `UNSUPPORTED`. Missing binaries, scripts, credentials, host capabilities,
or policy approvals are visible blockers. JStack must not:

- silently substitute a different provider;
- downgrade independent evidence to a self-check;
- fabricate a successful observation;
- install a dependency as a side effect of discovery;
- treat provider presence as specialist selection; or
- turn an unavailable optional provider into a runtime failure for unrelated
  JStack workflows.

No silent model fallback is allowed where model/provider identity is material
to a contract or evaluation.

## Result validation

Provider-specific schemas must be closed and bounded. Applicable verifiers
reject duplicate JSON keys, unknown fields, unsafe or symlinked paths,
oversized/changing files, stale observations, incomplete or truncated output,
foreign projects, candidate drift, provider drift, host drift, and attempted
authority escalation. A passing result must disclose what it observed and what
remains unproven.

The evidence verifier—not the provider—derives the JStack outcome. A failing
receipt can support a remediation request, but cannot grant the Builder write
scope. A candidate mutation invalidates candidate-bound provider evidence and
requires a fresh observation.

## State, privacy, and cost

Provider state must be private, project-namespaced, bounded, and
non-authorizing. Default JStack receipts retain digests and metadata rather
than raw page content, source, scanner output, prompts, model output, secrets,
cookies, or hidden reasoning. Network egress, persistent credentials, paid
model calls, and off-machine storage require an explicit contract, cost
boundary, and user/host authorization.

The initial browser runner is a local process boundary, not a sandbox. Its
scrubbed environment and process controls reduce risk but cannot prevent
repository code from using the current user's filesystem or network.

## Adding a provider

A future provider requires all of the following before release consideration:

1. a documented need that native/existing facilities cannot satisfy;
2. an immutable source and licence review;
3. a closed request, result, and evidence contract;
4. explicit effects, authorization prerequisites, state, privacy, cost, and
   failure semantics;
5. deterministic discovery with truthful unavailable/unsupported states;
6. bounded invocation separated from discovery and verification;
7. adversarial tests, candidate binding, and no-authority assertions;
8. artifact synchronization, provenance, migration, and rollback coverage; and
9. separately authorized release and installation.

## Related documents

- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [BROWSER_PROVIDER.md](BROWSER_PROVIDER.md)
- [CROSS_HOST_COMPATIBILITY.md](CROSS_HOST_COMPATIBILITY.md)
- [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md)
