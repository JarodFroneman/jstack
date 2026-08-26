# JStack × gstack Unified Engineering OS Domain Model

## Status and authority

This Stage 2 domain model implements the formal concepts required by the
authoritative Unified Engineering OS specification at the pinned JStack and
gstack baselines recorded in `BASELINE.md`. It does not select the Stage 3
target module layout, add a provider, execute gstack, change a command, or
authorize an external action.

The machine-readable source is
`mcp/jstack/schemas/unified-os-domain.v1.schema.json`. Its ten public anchors
are independently addressable as, for example,
`unified-os-domain.v1.schema.json#OperatingMode` and
`unified-os-domain.v1.schema.json#TeamPlan`.

## Formal model

```text
OperatingProfile ── governance floor ───────────────┐
OperatingMode ───── execution topology ─────────────┤
ScopeStrategy ───── bounded completion policy ──────┤
                                                    ▼
Department ── contains ──> Specialist ── selected by Team Composer
                                │
                                ├── inherits authority from CanonicalRole
                                ├── loads methods from Capability
                                └── may request bounded work from Provider
                                                                    │
                                                                    ▼
                                                         EvidenceContract

The composed, digest-bound result is a TeamPlan. It grants no authority.
```

The normative execution hierarchy remains:

```text
Operating Mode
  → Specialist
    → Canonical Role
      → Capability
        → Provider
          → Evidence Contract
```

`OperatingProfile`, `ScopeStrategy`, `Department`, and `TeamPlan` constrain or
describe that hierarchy; none is a substitute for one of its six layers.

## Contract index

| Concept | Schema version | Sole question answered | Must not become |
| --- | --- | --- | --- |
| `OperatingMode` | `jstack.operating-mode.v1` | How many physical agents and what execution topology may be used? | Specialist roster, permission set, or profile |
| `OperatingProfile` | `jstack.operating-profile.v1` | What governance floor applies? | Agent-count selector or risk-floor bypass |
| `ScopeStrategy` | `jstack.scope-strategy.v1` | How broadly may the authorized goal be completed? | Goal expansion or side-effect authority |
| `Department` | `jstack.department.v1` | Which organizational family contains related specialists? | Canonical role, physical team, or authority class |
| `Specialist` | `jstack.specialist.v1` | Which human-facing expertise identity may be selected? | Physical agent, role, capability, or permission |
| `CanonicalRole` | `jstack.canonical-role.v1` | What is the maximum authority ceiling? | Persona or task methodology |
| `Capability` | `jstack.capability.v1` | What bounded expertise and method are applied? | Permission, provider, or execution authority |
| `Provider` | `jstack.provider.v1` | What bounded runtime or external work can be requested? | Orchestrator, policy engine, or self-authorizing actor |
| `EvidenceContract` | `jstack.evidence-contract.v1` | What must be observed and verified to support a claim? | Approval, readiness shortcut, or deployment authority |
| `TeamPlan` | `jstack.team-plan.v1` | What expertise, independence, scopes, providers, and evidence does this task require? | Execution receipt, approval, or permission grant |

Every contract is closed with `additionalProperties: false`, has its own
`schemaVersion` and `entityKind` constants, and carries explicit non-authority
invariants. The aggregate schema uses `oneOf`, so a record must be exactly one
of the ten concepts.

## Contract semantics

### OperatingMode

The six existing public workflows are the allowed mode IDs:

- `j-stack-dev`
- `jstack-subagents`
- `jstack-full-team`
- `jstack-loop`
- `jstack-audit`
- `jstack-evidence-builder`

A mode declares topology and a bounded physical-agent budget. Specialist
selection remains delegated to the Team Composer. A selected mode can never
prevent a risk-floor-mandated independent check. Audit read-only behavior is a
mode invariant, not a convention inferred from a prompt.

### OperatingProfile

`solo`, `professional`, and `enterprise` are ordered governance floors. The
schema fixes their rule to `may-strengthen-never-weaken`: a stronger selected
profile may add controls, while a weaker profile cannot remove a control
required by task risk, policy, or explicit authority boundaries.

Profile does not choose specialists or physical-agent count. Those decisions
belong to the Team Composer under the selected mode.

### ScopeStrategy

The serialized IDs preserve the specification's `MINIMAL`, `BALANCED`, and
`COMPLETE` names exactly. Every strategy preserves explicit non-goals, grants
no authority, and requires explicit authority for broad scope.

- `MINIMAL`: smallest coherent change; no adjacent cleanup.
- `BALANCED`: complete the requested feature and required integration without
  redesigning unrelated systems.
- `COMPLETE`: complete an explicitly approved broad or greenfield surface.

Scope strategy cannot convert planning to implementation, diagnosis to repair,
building to deployment, or readiness to action.

### Department

A department is a discoverable organizational grouping. It has no physical
agent effect and no authority effect. Stage 5 will populate the specialist
directory; Stage 6 will select from it. Merely belonging to Security, Release,
or another department cannot grant a permission.

### Specialist

A specialist records stable identity, department, one canonical role,
capabilities, activation criteria, risk and independence requirements,
provenance, and optional provider requirements. It deliberately contains no
permission flags. Its authority mode is always `inherit-canonical-role`, and a
specialist-to-physical-agent binding is produced by the Team Composer.

This preserves:

```text
Specialist != Physical Agent
Role != Persona
```

### CanonicalRole

The existing eleven role IDs remain the authority classes:

```text
lead architect investigator builder reviewer qa security
devops product quant docs
```

Only a canonical role carries an authority ceiling. Its permission source is
JStack policy. Neither a specialist nor a capability may override that ceiling.
Existing role behavior is not changed by defining this contract; Stage 3 must
decide the target ownership boundary and later stages must use additive
migration.

### Capability

A capability contains expertise, a bounded method, activation signals, allowed
roles, evidence needs, provider needs, and provenance. Its permission mode is
always `inherit-canonical-role`, and its authority effect is `none`.

The atomic `Capability` contract complements the existing
`jstack.capability.catalog.v1` catalog. It does not replace or silently migrate
that catalog in Stage 2. Stage 3 must decide how the existing catalog evolves
without duplicating canonical data.

### Provider

A provider declares its optional runtime, maximum possible effects, required
authorization scopes, produced evidence contracts, bounded state, and
privacy-safe telemetry policy. Declared effects describe what a provider may
be technically capable of after authorization; they grant nothing.

Provider invariants are schema constants:

```text
orchestrator = false
canSelfAuthorize = false
authorityEffect = none
crossProjectAllowed = false
rawContentAllowed = false
silentEgressAllowed = false
```

An absent optional runtime reports `UNAVAILABLE` or `UNSUPPORTED`; JStack must
not fabricate substitute evidence.

### EvidenceContract

An evidence contract defines producers, observation fields, subject bindings,
status vocabulary, verification, and pass semantics. Its pass policy forbids
truncated, stale, failed, or incomplete evidence from becoming `PASS` and
requires successful reports to disclose what remains unproven.

Evidence has `authorizationEffect = none`. A valid artifact can support a
JStack decision; it cannot authorize remediation, Git mutation, release, or
deployment.

### TeamPlan

A Team Plan is digest-bound to project, repository, policy, approved Prompt
Compilation, Context Readiness, and exact composition inputs. It preserves the
requested task mode and records:

- required departments;
- selected specialists and canonical roles;
- assigned capabilities;
- physical-agent grouping;
- read and write scopes;
- independence requirements;
- evidence and provider requirements;
- why each specialist was selected;
- why departments were omitted;
- why individual specialists were omitted;
- a contradiction-resolution owner;
- bounded physical-agent and specialist limits.

The plan is descriptive and constraining. It is not an action approval. Schema
validation cannot prove referential integrity across future catalogs; the
Stage 6 Team Composer must validate every referenced ID and enforce agent-count,
role-ceiling, scope, and independence relationships deterministically.

## Anti-collapse rules

| Invalid collapse | Deterministic rejection rule |
| --- | --- |
| Mode treated as specialist list | `OperatingMode.specialistSelection` is fixed to `team-composer`; no specialist IDs exist on the mode |
| Profile treated as mode | Unique versions/kinds; profile has governance rank and no topology |
| Scope treated as authority | Scope has `authorityEffect = none` and cannot alter task mode or authorization |
| Department treated as team | Department has both authority and physical-agent effects fixed to `none` |
| Specialist treated as role | Specialist references exactly one canonical role; it cannot carry an authority ceiling |
| Specialist treated as physical agent | Specialist binding is `composer-assigned`; only TeamPlan maps physical agents |
| Capability treated as permission | Permission mode is fixed to `inherit-canonical-role` |
| Provider treated as authority | Provider is not an orchestrator, cannot self-authorize, and exposes authorization prerequisites |
| Evidence treated as approval | Evidence authorization effect is fixed to `none`; invalid/stale evidence cannot pass |
| TeamPlan treated as execution receipt | Plan permission/evidence invariants and authority effect are fixed constants |

## Validation boundary

Stage 2 validation proves:

1. the schema is Draft 2020-12 and syntactically valid when `jsonschema` is
   available;
2. all ten contracts have unique versions, entity kinds, and public anchors;
3. representative records validate only against their intended contract;
4. authority-separation constants cannot be changed without a validation
   failure;
5. unknown fields are rejected at every object boundary.

Stage 2 does not yet prove:

- directory/catalog referential integrity;
- risk routing or profile selection;
- dynamic team composition;
- provider availability or sandboxing;
- evidence production or candidate binding;
- migration of existing fixed team behavior.

Those are intentionally assigned to later specification stages.

## Stage 2 advance gate

The contracts are independently versioned, structurally disjoint, closed, and
covered by negative interchangeability tests. The six execution layers and the
four supporting concepts cannot be accidentally serialized as one another.

**Advance-gate decision:** Stage 2 is complete when the schema, distribution
sync, contract-separation tests, and existing compatibility checks pass. That
gate authorizes Stage 3 ADR design only; it authorizes no provider execution,
runtime side effect, Git action, release, deployment, or production mutation.
