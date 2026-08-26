# Stage 16 — Security and Supply-Chain Hardening

## Status and authority

| Item | Value |
| --- | --- |
| Objective | Make security-tool coverage, independence, gaps, and claim limits explicit |
| Dependency policy | No new mandatory scanner or runtime dependency |
| Authority effect | None; scanners provide evidence only |
| Advance gate | **PASS** — critical provider and receipt boundaries survive malicious input |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

Stage 16 first inventories existing JStack controls, then selects a
proportionate provider-neutral evidence plan from
`mcp/jstack/providers/security-tooling.v1.json`.

| Control | State | Independence | Claim limit |
| --- | --- | --- | --- |
| Bounded secret scan | Active | JStack self-check | Heuristic coverage, not proof of no secrets |
| Browser-provider hardening | Active when selected | JStack self-check | Local process is not an OS/network sandbox |
| External SAST evidence | Optional | Independent provider | Binding/completeness validation, not producer honesty |
| Offline OSV SCA | Optional | Independent provider | Installed scanner and local database coverage only |
| Provenance/attestation verification | Active for production | External control | Digest identity, not publication authority |
| SPDX/CycloneDX SBOM evidence | Optional | External control | Presence does not prove completeness or safety |
| Workflow static security | Active from elevated risk | JStack self-check | Supported static syntax only |

High and production risk require independent scanner evidence. If an
independent provider is unavailable, the plan remains incomplete rather than
silently substituting a JStack self-check. Tool availability never grants
remediation, Git, release, deployment, or production authority.

## Threat coverage

The focused adversarial suite covers command smuggling, prompt injection,
external and credential-bearing URLs, path traversal, symlinks, stale and
duplicate evidence, oversized or changing output, repository mutation,
provider/host/candidate drift, and attempted authority escalation. The browser
runner closes stdin, avoids a shell, scrubs secrets, isolates HOME, caps
output, bounds time, and terminates its process group. Repository-controlled
code still runs with the current user's filesystem and network privileges;
untrusted code requires external isolation.

`mcp/jstack/providers/security.py` only validates the catalog and creates a
digest-bound security-provider plan. It does not install or run a scanner,
send source to a vendor, store raw scanner output, make a security guarantee,
or authorize a fix.

## Integration and compatibility

The plan is included in Unified Team output as `securityProviderPlan`; its
digest is signed and recomputed at dispatch. The implementation adds no public
tool, command, vendor SDK, network import, mandatory dependency, telemetry, or
silent fallback. Existing Launch Assurance remains the consumer for separately
produced target-bound security evidence.
