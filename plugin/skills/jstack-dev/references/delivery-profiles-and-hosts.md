# Delivery Profiles, Security, and Host Contracts

## Operating profile

Pass `operating_profile` explicitly to `jstack_plan` and `jstack_team_plan`:

- `solo`: low ceremony with proportional verification;
- `professional`: balanced independent review and QA; or
- `enterprise`: strict separation plus policy and risk-register evidence.

If the user has not selected a profile, use `professional`. Never infer it
from `quality_level`, team mode, task size, or cost preference. A profile may
strengthen evidence and independence only; it cannot lower risk floors, expand
scope, change task mode, or authorize an action.

## Host contract

Pass the actual current `host_id`. The current release catalog recognizes
`codex`, `claude-code`, and `generic-mcp`. Consume only capabilities marked
`AVAILABLE` in the returned `hostContract`. `UNAVAILABLE` and `UNSUPPORTED`
must remain unavailable; do not emulate them or claim parity.

Methodology remains portable across hosts. Host capability affects physical
execution only. A host contract never authorizes local execution, source
edits, browser access, Git, release, deployment, or production actions.

## Professional delivery pipeline

The returned `professionalDeliveryPipeline` is the ordered evidence projection
of the exact Team Plan:

```text
plan → implement → review → QA → browser QA → security → evidence
```

It is not a scheduler or action authority. Follow only phases marked required.
Only the implement phase may observe source mutation, and only through the
Team Plan's exact bounded writer. All candidate-bound evidence becomes stale
after a candidate change and must be regenerated.

## Security provider plan

Read `securityProviderPlan` before making a security or readiness claim. Use
its selected controls and disclose every gap and claim boundary. High and
production risk require independent scanner evidence. Never substitute a
JStack self-check for required independent evidence, install a scanner without
authority, or claim that a clean scan proves the absence of vulnerabilities.

## Release choreography

Pass the intended `release_strategy` (`direct`, `canary`, or `blue-green`) to
`jstack_release_readiness`. The returned `releaseChoreography` presents the
required candidate, tests, review, security, browser, launch, audit, canary,
monitor, and rollback state. It always has `executionAuthorized=false`.
Readiness may tell the host to request a separately authorized provider action;
it never executes or authorizes one.
