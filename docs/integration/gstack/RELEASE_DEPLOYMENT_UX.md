# Stage 15 — Release, Canary, and Deployment UX

## Status and authority

| Item | Value |
| --- | --- |
| Objective | Present a coherent release-readiness path for direct, canary, and blue-green strategies |
| Integration point | Existing `jstack_release_readiness` result |
| Authority effect | None; readiness remains separate from external-action authority |
| Advance gate | **PASS** — readiness cannot independently trigger production |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

`mcp/jstack/release/choreography.py` projects existing release-readiness facts
into an ordered, digest-bound UX:

```text
candidate → tests → review → security → browser → launch → audit
          → readiness → separate action authority → canary → monitor → rollback
```

The projection supports `direct`, `canary`, and `blue-green` as presentation
strategies. Canary requires a canary plan. Production requires monitoring and
rollback plans. Applicable browser, launch, and independent audit controls are
shown explicitly rather than inferred from a green summary.

## Hard boundary

`executionAuthorized` is always false and `authorityEffect` is always `none`.
A passing readiness result changes only the next displayed step to request a
separately authorized host/provider action within the user's explicit scope.
It does not execute a command, call a deployment provider, mutate Git, create
a release, publish an artifact, or touch production.

The existing readiness handler remains responsible for candidate, tests,
review, security, UI, launch, audit, policy, and approval-reference checks.
Stage 15 does not replace those controls. It adds `release_strategy` as an
optional input and returns `releaseChoreography` after readiness has been
calculated.

## Compatibility, provenance, and tests

The implementation adds:

- `mcp/jstack/release/choreography.py` and its package export;
- `mcp/jstack/schemas/release-choreography.v1.schema.json`; and
- `tests/test_release_choreography.py`.

It adapts general release/canary ergonomics researched in the pinned gstack
`canary/`, `ship/`, `land-and-deploy/`, and `setup-deploy/` surfaces, while
rejecting their control plane, automatic actions, state, installer, prompts,
and provider authority. The implementation is original JStack code.

Focused tests prove that ready releases still await separate authority,
missing canary or readiness evidence blocks the applicable stage, unknown
strategies fail closed, and tampering or attempted authority escalation is
rejected.
