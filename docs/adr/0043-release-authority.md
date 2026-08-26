# ADR 0043: Release Readiness Never Authorizes Shipping Or Deployment

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0006](0006-external-action-authorization-boundary.md),
  [ADR 0008](0008-host-native-action-safety.md), and
  [ADR 0009](0009-launch-assurance-v2.md)

## Context

gstack includes useful shipping, landing, canary, and deployment ergonomics.
Those workflows can also commit, push, merge, deploy, monitor, or roll back.
Combining readiness and action would let a generated receipt or adapted method
exercise authority the user did not grant.

## Decision

JStack remains the release-assurance owner. Readiness can bind tests, review,
security, runtime QA, supply chain, candidate, target, and rollback evidence.
It always has `executionAuthorized=false` or an equivalent non-authorizing
semantic.

Git writes, PR actions, release publication, deployment, production mutation,
canary changes, and rollback each require exact user scope plus ordinary host
or provider permission at action time. Authorizations are target-, action-,
project-, policy-, candidate-, and expiry-bound. A prior build authorization
does not imply deploy authority.

Selected gstack ergonomics may be adapted as status UX or wrapped as separate
providers. No provider may infer approval from readiness, and no automatic
chain may silently add a later action.

## Rejected Alternatives

- Import `ship` or `land-and-deploy` as a trusted command: rejected because it
  duplicates release authority.
- One blanket release receipt: rejected because actions have distinct scopes.
- Deployment on green tests: rejected because quality evidence is not consent.

## Consequences

Release flow remains explicit and auditable. Users must authorize external
steps, while bounded providers can still improve execution ergonomics later.
