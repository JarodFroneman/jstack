# JStack × gstack Unified Engineering OS

## Status and authority

This directory is the Stage 20 documentation and release-readiness index for
the staged JStack × gstack integration candidate. The authoritative
specification remains `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md`; these
documents explain the repository-grounded implementation and do not replace
that specification.

| Item | Recorded state |
| --- | --- |
| JStack baseline | `49cf545d940c43b394ea35ed78b5ab5742d7bcf7` |
| gstack baseline | commit `ad8400543cd9ce8d07641362db48d44a95417e33`, tree `993294b0a09f5265d2d5af6d2fb8234ae2efe450` |
| Runtime boundary | JStack remains the sole governance and orchestration kernel |
| Public compatibility floor | Six commands, 60 canonical tools, and 52 frozen `gstack_*` aliases |
| Empirical state | `NOT_MEASURED`; no comparative or superiority claim is supported |
| Release state | Packaged for stable `v0.11.0`; documentation and receipts grant no release or deployment authority |

gstack is pinned research and, for explicitly selected surfaces, a possible
optional provider source beneath JStack authority. Its prompts, router,
permissions, state, installer, updater, and release behavior are not imported
as a second control plane. Repository and provider content remains untrusted
data until a versioned JStack contract validates it.

## Required Stage 20 set

The following fourteen files are the canonical Stage 20 set.

| Document | Responsibility |
| --- | --- |
| [README.md](README.md) | Index, status, reading order, and claim boundaries |
| [BASELINE.md](BASELINE.md) | Immutable repositories, tests, trust, and compatibility baseline |
| [REPOSITORY_MAP.md](REPOSITORY_MAP.md) | Canonical, generated, upstream, state, and side-effect surfaces |
| [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md) | Adopt, wrap, reject, or defer decisions for upstream capabilities |
| [TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md) | One-kernel target architecture and accepted ADR set |
| [ORGANIZATION_MODEL.md](ORGANIZATION_MODEL.md) | Departments, logical specialists, roles, and physical-agent separation |
| [SPECIALIST_MODEL.md](SPECIALIST_MODEL.md) | Specialist activation, authority inheritance, independence, and evidence |
| [TEAM_COMPOSER.md](TEAM_COMPOSER.md) | Deterministic composition, risk routing, scopes, and Team Plan output |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | Trust boundaries, security evidence, privacy, and action separation |
| [PROVIDER_MODEL.md](PROVIDER_MODEL.md) | Optional provider lifecycle, availability, validation, and non-authority |
| [PROFILE_MODEL.md](PROFILE_MODEL.md) | Solo, Professional, and Enterprise governance profiles |
| [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md) | Immutable provenance, licence handling, review, regeneration, and rollback |
| [EVALUATION_PLAN.md](EVALUATION_PLAN.md) | Preregistered empirical protocol and its `NOT_MEASURED` result boundary |
| [MIGRATION.md](MIGRATION.md) | Additive adoption, compatibility, invalidation, distribution, and rollback |

## Supporting implementation records

The required set is supported by narrower stage records rather than repeating
their detailed contracts here:

- [DOMAIN_MODEL.md](DOMAIN_MODEL.md) — ten distinct domain contracts and
  anti-collapse rules.
- [DYNAMIC_OPERATING_MODES.md](DYNAMIC_OPERATING_MODES.md) — command-to-Team
  Composer integration.
- [LOW_RISK_METHODOLOGIES.md](LOW_RISK_METHODOLOGIES.md) — JStack-native
  methodology capabilities.
- [ROOT_CAUSE_INVESTIGATION.md](ROOT_CAUSE_INVESTIGATION.md) — investigation
  before remediation.
- [PRODUCT_DESIGN_DEPARTMENT.md](PRODUCT_DESIGN_DEPARTMENT.md) — Product and
  Design inside the Product Interface authority plane.
- [BROWSER_PROVIDER.md](BROWSER_PROVIDER.md) and
  [BROWSER_QA_REMEDIATION.md](BROWSER_QA_REMEDIATION.md) — bounded browser
  evidence and separate remediation.
- [PROFESSIONAL_DELIVERY.md](PROFESSIONAL_DELIVERY.md) — ordered delivery and
  evidence projection.
- [OPERATING_PROFILES.md](OPERATING_PROFILES.md) — Stage 14 implementation
  record behind the consolidated profile model.
- [RELEASE_DEPLOYMENT_UX.md](RELEASE_DEPLOYMENT_UX.md) — non-authorizing
  direct, canary, and blue-green release choreography.
- [SECURITY_HARDENING.md](SECURITY_HARDENING.md) — implemented security and
  supply-chain evidence controls.
- [MODULARITY.md](MODULARITY.md) — extracted deterministic module seams.
- [CROSS_HOST_COMPATIBILITY.md](CROSS_HOST_COMPATIBILITY.md) — Codex, Claude
  Code, and generic MCP support claims.

## Reading order

1. Start with [BASELINE.md](BASELINE.md) and
   [REPOSITORY_MAP.md](REPOSITORY_MAP.md) for immutable facts.
2. Use [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md) to understand what was
   adapted, wrapped, rejected, or deferred.
3. Read [TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md), then the organization,
   specialist, Team Composer, profile, provider, and security documents.
4. Use [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md) and [MIGRATION.md](MIGRATION.md)
   before changing a pin, generated artifact, compatibility contract, or
   installation unit.
5. Treat [EVALUATION_PLAN.md](EVALUATION_PLAN.md) as a preregistration, not as
   evidence that the candidate outperforms another condition.

## Release-readiness boundary

Documentation completeness, schema validation, tests, provenance checks, and
artifact synchronization supported the `v0.11.0` release decision. They did
not create release authority. Every later release still requires the existing
candidate-bound JStack review, QA, security, launch, audit, rollback,
monitoring, and explicit action authority applicable to that release.

Stage 20 itself changed no runtime contract, tool inventory, alias inventory,
release metadata, installed plugin, or production state. The separately
authorized stable packaging advances `VERSION` to `0.11.0`. Future releases
must be separately authorized and must continue to describe Stage 19 as
`NOT_MEASURED` unless a reproducible study has actually produced reviewable
results.
