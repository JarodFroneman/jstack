# JStack Unified Security Model

## Security objective

The unified candidate strengthens evidence and specialist coverage without
creating a second policy engine or claiming immunity from attack. JStack
remains the authority for task mode, risk floors, scope, permissions, evidence,
audit, and release readiness. gstack sources, repository content, provider
output, browser pages, screenshots, documents, logs, and model output are data,
not executable instructions or action authority.

## Trust boundaries

```text
explicit user authority + host policy
              │
              ▼
JStack Prompt Compiler / Context Readiness
              │
              ▼
risk floors + canonical roles + Team Composer
              │
              ├─ repository and external content (untrusted data)
              └─ optional provider request (bounded and explicit)
                            │
                            ▼
                 untrusted provider result
                            │
                            ▼
schema + path + digest + candidate + freshness verification
                            │
                            ▼
non-authorizing evidence / audit / release-readiness decision
```

No lower layer may weaken host policy, JStack policy floors, explicit user
limitations, or ordinary permission controls.

## Current security-control inventory

`mcp/jstack/providers/security-tooling.v1.json` records seven provider-neutral
controls. The accompanying Stage 16 implementation record is
[SECURITY_HARDENING.md](SECURITY_HARDENING.md).

| Control family | Current state | Claim boundary |
| --- | --- | --- |
| Bounded secret scan | Active JStack self-check | Heuristic patterns do not prove that no secret exists |
| Browser-provider hardening | Active when selected | Local execution is not an OS or network sandbox |
| External SAST evidence | Optional independent provider | Binding validation does not prove producer honesty or complete rules |
| Offline OSV SCA | Optional independent provider | Coverage is limited to the installed scanner and local database |
| Provenance/attestation verification | Active for production | Digest identity does not authorize publication |
| SPDX/CycloneDX evidence | Optional external control | An SBOM does not prove completeness or safety |
| Workflow static security | Active from elevated risk | Static parsing covers only supported syntax |

Tool presence never grants authority. A scanner pass never proves the absence
of vulnerabilities. Raw scanner output is not stored by the catalog.

## Risk and independence

Risk is monotonic: repository evidence, policy, or the user's request may raise
it, while profile, mode, scope strategy, specialist preference, or provider
availability may not lower it. Normal risk requires proportional secure-
development evidence and independent QA. Elevated, high, and production risk
add architecture, security, release, rollback, monitoring, and independent
assurance according to the Team Composer and Launch Assurance policies.

High and production security plans require independent scanner evidence. If a
required independent provider is unavailable, evidence remains incomplete; a
JStack self-check is not silently relabelled as independent proof. Security,
QA, audit, and release findings do not authorize remediation or external
action.

## Provider and hostile-content controls

Bounded providers must declare effects, required authorization scopes,
produced evidence contracts, state, and privacy behavior. Discovery is
read-only. Invocation requires the exact authority and host support. Results
are treated as hostile until closed-schema, duplicate-key, path, size, digest,
freshness, project, repository, candidate, host, provider, and completeness
checks pass.

The browser wrapper additionally rejects traversal, credential-bearing and
external routes, closes stdin, avoids a shell, scrubs secrets, isolates HOME,
caps output, bounds time, detects repository mutation, and terminates its
process group. It still executes repository-controlled code with the current
user's filesystem and network privileges. Untrusted code requires separately
provisioned isolation.

Prompt injection or destructive-action instructions embedded in `README`,
`AGENTS.md`, code comments, issues, logs, web pages, screenshots, documents, or
provider results cannot override the authorized instruction hierarchy. An
authorized host instruction file remains subject to host and JStack policy.

## Privacy and telemetry

Default receipts and telemetry contain binding metadata, counts, status, and
digests—not raw prompts, source contents, browser content, scanner output,
model output, command output, credentials, secrets, reviewer identity, or
hidden reasoning. State is project-bound and cross-project reuse is prohibited
unless an explicit future contract says otherwise.

Provider secrets are not copied into prompts or repository artifacts. Network
egress, vendor submission, persistent browser state, cookies, tunnels, and
off-machine telemetry require explicit provider contracts and authority; they
are not implied by the current candidate.

## Release and action separation

Passing tests or evidence can satisfy a typed requirement but cannot commit,
push, merge, tag, publish, release, deploy, or mutate production. Release
readiness still requires the exact candidate, current tests, review, security,
launch, audit, rollback, monitoring, and explicit environment approvals that
active policy demands. A separate user-authorized host/provider action is
required after readiness.

Stage 20 documents these boundaries only. It adds no scanner, sandbox, vendor
SDK, network call, credential, provider fallback, action permission, or
security guarantee.

## Related documents

- [PROVIDER_MODEL.md](PROVIDER_MODEL.md)
- [PROFILE_MODEL.md](PROFILE_MODEL.md)
- [BROWSER_PROVIDER.md](BROWSER_PROVIDER.md)
- [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md)
- [RELEASE_DEPLOYMENT_UX.md](RELEASE_DEPLOYMENT_UX.md)
