# JStack Unified Organization Model

## Status and sources

The organization is a JStack-native logical directory, not an imported gstack
team or a fixed physical-agent roster. Its canonical data and validator are:

- `mcp/jstack/organization/directory.v1.json`;
- `mcp/jstack/organization/directory.py`; and
- `mcp/jstack/schemas/specialist-directory.v1.schema.json`.

The current directory contains nine departments and 35 specialists. Those
counts describe discoverable professional functions. They do not require 35
agents and do not grant 35 separate permission sets.

## Departments

| Department | Specialist count | Bounded purpose |
| --- | ---: | --- |
| Audit & Assurance | 4 | Independent, read-only correctness, security, architecture, operational, and release assurance |
| Design | 5 | Product experience, systems, motion, and accessibility without implementation authority |
| Domain Specialists | 3 | Financial, quantitative, and data expertise where generic review is insufficient |
| Engineering | 7 | Architecture and bounded implementation through canonical JStack roles |
| Investigation & Reliability | 3 | Reproduction, hypothesis testing, root cause, and operational reliability |
| Product | 3 | Outcomes, scope, user value, developer experience, and handoff |
| Quality | 4 | Independent verification without remediation authority |
| Release & Operations | 2 | Delivery, rollback, monitoring, and readiness without action authority |
| Security | 4 | Application, identity, supply-chain, and independent security assurance |

Every department fixes `selectionPolicy` to dynamic material need and both
`authorityEffect` and `physicalAgentEffect` to `none`.

## Organization hierarchy

```text
Department
  └─ Specialist (logical expertise identity)
       ├─ exactly one CanonicalRole (authority ceiling)
       ├─ one or more Capabilities (bounded methods)
       ├─ optional Provider requirements
       └─ Evidence and independence requirements

Team Composer
  └─ assigns selected specialists to bounded Physical Agents
```

The directory organizes expertise; the Team Composer selects it. Canonical
roles remain the only permission classes, and the selected operating mode
limits physical topology. This preserves all of the following distinctions:

```text
Department != team
Specialist != role
Specialist != physical agent
Capability != permission
Provider != authority
Evidence != approval
```

## Selection and integrity

The directory binds its capability-catalog version and digest. The validator
rejects unknown departments, specialists, canonical roles, capabilities,
providers, provenance records, duplicate identifiers, invalid cross-references,
and any specialist permission override. Every specialist must:

- belong to exactly one declared department;
- inherit exactly one of JStack's eleven canonical roles;
- reference only catalogued capabilities;
- declare bounded activation signals;
- declare risk and independence requirements;
- use `composer-assigned` physical-agent binding;
- use `inherit-canonical-role` authority mode; and
- set `permissionOverridesAllowed` to false.

Directory validation proves structural integrity. It does not decide whether a
specialist is materially required for a particular task. That decision belongs
to the deterministic Team Composer and its versioned policy.

## Dynamic organization, stable authority

The organization is dynamic in function coverage but stable in authority.
Tiny work can select one Lead specialist on one physical agent. Authentication,
security, finance, infrastructure, migration, or production work can select
multiple departments and independent reviewers. In both cases, permissions
come from the same canonical-role policy and remain bounded by the user's task
mode and scopes.

Audit, QA, security, and release specialists cannot convert a finding into a
fix or an external action. A Builder cannot absorb an independent reviewer
onto the same physical agent when the risk policy requires separation. A
missing mandatory specialist or impossible independence requirement fails
closed rather than weakening the organization.

## Provenance and privacy

The directory records source provenance for the pinned MIT-licensed gstack
research baseline and the authoritative JStack specification. It is an
original JStack catalog: upstream personas, prompt bodies, permissions,
installer state, and runtime routing are not copied.

Team Plans and receipts bind directory and policy digests. They do not need to
persist raw prompts, source contents, model output, secrets, or hidden
reasoning. A directory update invalidates dependent composition evidence and
requires regeneration, focused tests, provenance checks, and distribution
synchronization before release consideration.

## Related documents

- [SPECIALIST_MODEL.md](SPECIALIST_MODEL.md)
- [TEAM_COMPOSER.md](TEAM_COMPOSER.md)
- [DOMAIN_MODEL.md](DOMAIN_MODEL.md)
- [PROFILE_MODEL.md](PROFILE_MODEL.md)
- [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md)
