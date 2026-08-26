# JStack Specialist Model

## Purpose

A Specialist is a stable, human-facing expertise identity selected for a
material task need. It is neither a new permission class nor necessarily a
separate process. The canonical record shape is defined by
`mcp/jstack/schemas/specialist-directory.v1.schema.json` and populated by
`mcp/jstack/organization/directory.v1.json`.

The current directory contains 35 specialists across nine departments. The
Team Composer may assign several compatible specialists to one physical agent,
subject to the operating-mode budget, canonical-role ceiling, write ownership,
and independence edges.

## Separation of concerns

| Concept | Answers | Does not answer |
| --- | --- | --- |
| Specialist | Which professional expertise is materially needed? | What may execute or mutate? |
| Canonical Role | What is the maximum permission ceiling? | Which persona or method is preferred? |
| Capability | Which bounded expertise and method applies? | Which permissions are granted? |
| Physical Agent | Where may compatible selected work execute? | Which logical functions were required? |
| Provider | Which optional runtime may produce bounded work or evidence? | Whether the action is authorized or successful |
| Evidence Contract | What observations support a claim? | Whether remediation, release, or deployment is authorized |

The normative chain is:

```text
Operating Mode
  → Specialist
    → Canonical Role
      → Capability
        → optional Provider
          → Evidence Contract
```

Profiles, scope strategy, risk, project state, and user authority constrain
that chain; none can replace a layer.

## Specialist contract

Each specialist declares:

- a stable ID, display name, and description;
- one department and one canonical role;
- capability IDs;
- activation domains, classifications, changed surfaces, and task signals;
- mandatory/prohibited risk classes;
- independence requirements and roles from which separation is required;
- optional provider requirement IDs; and
- immutable source-provenance IDs.

The fixed safety fields are:

```text
physicalAgentBinding = composer-assigned
authorityMode = inherit-canonical-role
permissionOverridesAllowed = false
```

Adding persuasive persona text cannot alter those fields or the JStack role
policy.

## Activation and omission

Selection is deterministic and evidence-led. Repository classification,
changed surfaces, user task signals, requested task mode, effective risk,
profile controls, methodology requirements, and explicit permitted specialist
IDs feed one Team Composer. Selection reasons and omission reasons are included
in the Team Plan so a reviewer can see both why expertise was added and why it
was not.

An explicit specialist request is still constrained by the directory, role
ceiling, policy, risk, scope, and physical-agent budgets. A forbidden
specialist is rejected. A mandatory specialist cannot be omitted because a
lower profile or smaller team is preferred. Provider availability cannot cause
a specialist to be selected or skipped.

## Independence and write ownership

Independence is a graph constraint, not a title. When policy requires
independent QA, security, audit, quantitative, architecture, or release review,
the relevant specialist cannot share a physical agent with the writer or
release actor it must evaluate.

Only an authorized `implement` or `fix` Team Plan can contain source-write
scope. Exactly one selected Builder owns the non-overlapping bounded source
write scope. Reviewers, QA, auditors, security specialists, providers, and
evidence producers do not gain remediation authority from their findings.

## Evidence and receipts

Selected capabilities declare required evidence and stop conditions. Provider
results are normalized through closed contracts and verified before they can
support those evidence requirements. The signed Team Plan binds the exact
directory, policy, selection inputs, project, repository, Prompt Compilation,
Context Readiness, scopes, and physical assignment.

That receipt is descriptive and constraining. It cannot grant repository
writes, Git actions, provider execution, release, deployment, production
mutation, or another external action. A material goal, task-mode, risk,
profile, scope, catalog, provider, repository, or candidate change invalidates
the affected downstream evidence.

## Adaptation boundary

The pinned gstack sources informed professional-function coverage. JStack does
not install upstream specialists, execute upstream prompt bodies, import their
persona or state model, or accept upstream permissions. New specialists must
be original JStack records with explicit provenance, a canonical role,
bounded activation, test coverage, and no authority override.

## Related documents

- [ORGANIZATION_MODEL.md](ORGANIZATION_MODEL.md)
- [TEAM_COMPOSER.md](TEAM_COMPOSER.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [PROVIDER_MODEL.md](PROVIDER_MODEL.md)
