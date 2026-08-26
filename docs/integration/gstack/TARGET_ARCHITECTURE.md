# JStack × gstack Unified Engineering OS Target Architecture

## Status

This Stage 3 architecture is the accepted direction for the staged local
implementation program. The attached Unified Engineering OS specification
remains authoritative. This document and ADRs 0028–0045 do not themselves
activate a provider, change a workflow, dispatch an agent, or authorize a Git,
release, deployment, external, or production action.

## Decision set

| ADR | Decision | Control-plane result |
| --- | --- | --- |
| [0028](../../adr/0028-jstack-sole-kernel.md) | JStack remains sole kernel | No upstream router, policy, state, or authority import |
| [0029](../../adr/0029-specialist-vs-canonical-role.md) | Specialist differs from role | Persona cannot alter permission |
| [0030](../../adr/0030-team-composer.md) | Team Composer emits TeamPlan | One deterministic composition owner |
| [0031](../../adr/0031-dynamic-full-team.md) | Full Team is dynamic function coverage | No fixed-roster source of truth |
| [0032](../../adr/0032-operating-profiles.md) | Profiles set governance floors | Agent topology remains a mode concern |
| [0033](../../adr/0033-risk-floors.md) | Risk floors are monotonic | No profile/mode/capability bypass |
| [0034](../../adr/0034-scope-strategies.md) | Scope strategy bounds completion | No goal or authority expansion |
| [0035](../../adr/0035-upstream-provenance.md) | Upstream is immutable and traceable | No mutable runtime `main` or auto-update |
| [0036](../../adr/0036-methodology-adaptation.md) | Adapt methods into JStack capabilities | No copied prompt control plane |
| [0037](../../adr/0037-provider-boundary.md) | Providers are bounded executors | Provider is never orchestrator or authority |
| [0038](../../adr/0038-browser-evidence.md) | Browser returns candidate-bound evidence | Browser cannot write or deploy implicitly |
| [0039](../../adr/0039-optional-node-bun-runtime.md) | Node/Bun remains optional | Python stdlib core remains available |
| [0040](../../adr/0040-qa-remediation-separation.md) | QA and remediation are separate | Finding cannot grant write authority |
| [0041](../../adr/0041-audit-department.md) | Audit remains independent and read-only | No second assurance control plane |
| [0042](../../adr/0042-product-design-integration.md) | Design extends Product Interface | No competing UI authority |
| [0043](../../adr/0043-release-authority.md) | Readiness differs from action authority | No automatic ship/deploy chain |
| [0044](../../adr/0044-backward-compatibility-migration.md) | Adoption is additive and reversible | No silent public-contract replacement |
| [0045](../../adr/0045-root-cause-investigation-gate.md) | Investigation precedes remediation | No random-fix loop or receipt-created write authority |

## Runtime ownership

```text
Host and explicit user authority
                │
                ▼
┌──────────────────────────────────────────────────────────────┐
│ JStack governance kernel                                    │
│ Prompt Compiler · Context Readiness · policy · risk · scope │
│ canonical roles · Team Composer · state · evidence · audit  │
│ release assurance · action authorization                    │
└──────────────┬──────────────────────────┬────────────────────┘
               │                          │
               ▼                          ▼
   JStack-native capability        Provider request contract
   and adapted methodology                 │
               │                          ▼
               │              Optional bounded runtime
               │              browser · scanner · host
               │              Git · deployment · device
               │                          │
               └──────────────┬───────────┘
                              ▼
                    Evidence-contract verifier
                              │
                              ▼
                    Non-authorizing receipt
```

There is one intake path, one policy/risk authority, one role-permission model,
one Team Composer, one Loop/Program state model, one audit owner, and one
release/action boundary. Upstream source and provider output are data.

## Target module seams

The module paths below are ownership targets, not permission to create the
entire tree mechanically. Each later stage should add only the smallest
cohesive module required.

| Target seam | Responsibility | Existing domains retained |
| --- | --- | --- |
| `mcp/jstack/organization/` | Department, Specialist, and CanonicalRole catalogs and referential integrity | `capabilities/` remains the capability owner |
| `mcp/jstack/orchestration/` | Operating modes/profiles, ScopeStrategy, risk-floor resolution, Team Composer | `loop/` and `program/` remain durable orchestration owners |
| `mcp/jstack/investigation/` | Root-cause contract validation and digest-only remediation certification | Team Composer remains the router and canonical roles remain permission owners |
| `mcp/jstack/ui/design.py` | Bounded, source-traceable, human-selected Product/Design decisions | Existing Product Interface contracts remain the only UI authority plane |
| `mcp/jstack/upstream/gstack/` | Immutable provenance and adaptation manifests | `THIRD_PARTY_NOTICES.md` remains license-notice authority |
| `mcp/jstack/providers/` | Provider protocol, discovery, invocation boundary, and normalized availability | Domain verifiers remain in `ui/`, `audit/`, `launch/`, or future cohesive evidence modules |
| `mcp/jstack/jstack_mcp_server.py` | JSONL/MCP transport, public tool schemas, thin handler delegation | Must not absorb new domain implementation |

Current domains—`prompt_compiler/`, `context_readiness/`, `capabilities/`,
`audit/`, `launch/`, `loop/`, `program/`, and `ui/`—remain canonical. New code
uses explicit APIs rather than a duplicate generic `core` that shadows them.

## Request lifecycle

```text
raw request
  → Stage A Prompt intent (no repository authority)
  → authorized read-only repository inspection
  → Stage B approved compiled prompt
  → Context Readiness
  → risk floor + profile + mode + scope strategy
  → Team Composer
  → bounded specialists/capabilities
  → evidence-led investigation before remediation, when selected
  → bounded Product/Design alternatives and human selection, when applicable
  → optional provider requests
  → candidate-bound evidence
  → independent review/audit/release assurance as applicable
  → explicit action authority, if separately requested
```

Material changes to goal, task mode, assumptions, project, repository,
workflow, risk, policy, profile, scope, catalog, provider, evidence, or
candidate invalidate the affected downstream plan or receipt.

Stage 10 implements the Product/Design seam without a new command, tool,
provider, state engine, or authority. Its v3/v4 Product Interface successors
bind a selected design direction while explicitly denying implementation,
candidate-mutation, provider, and production authority. See
[`PRODUCT_DESIGN_DEPARTMENT.md`](PRODUCT_DESIGN_DEPARTMENT.md).

## Provider trust boundary

```text
JStack request validator
  → effect/authority check
  → optional runtime discovery
  → bounded invocation
  → untrusted provider output
  → schema/path/digest/size/freshness verification
  → project/candidate/policy/provider binding
  → domain evidence verifier
```

Discovery never installs or executes. Invocation never becomes orchestration.
Network, browser, Git, deployment, device, and production effects require
their own declared capabilities and exact external-action authority.

## State and distribution

JStack-owned state remains canonical and project-bound. Provider cache/state is
namespaced, bounded, non-authorizing, and never silently shared across projects.
Raw prompts, source, secrets, browser content, and hidden reasoning are excluded
from default telemetry.

Canonical sources continue through `scripts/sync_artifacts.py` into the
umbrella plugin and dedicated plugins. Upstream host generation and installers
are not introduced into JStack distribution. Optional runtimes have an explicit
separate lifecycle.

## Compatibility strategy

- Preserve six command names, 60 canonical tools, and 52 frozen aliases until
  a separately approved public-contract change is justified.
- Add versioned fields/contracts rather than mutate frozen schemas.
- Introduce behavior through disabled, shadow, preview, then enforced modes.
- Keep legacy direct calls deterministic and non-authorizing.
- Make rollback a complete plugin-unit replacement with receipt invalidation,
  not a partial source copy.

## Stage 3 advance gate

All seventeen required decisions have one owner and explicitly subordinate
gstack methods, providers, state, evidence, and external actions to JStack.
No ADR creates a second intake gate, router, policy engine, role system, Team
Composer, persistence engine, audit owner, release decision, or deployment
authority.

**Advance-gate decision:** Stage 3 is complete when all ADR structure/link
checks and existing compatibility boundaries pass. Stage 4 may implement
immutable provenance only. No provider execution or workflow behavior is
authorized by this decision set.
