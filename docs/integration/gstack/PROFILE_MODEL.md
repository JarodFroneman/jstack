# JStack Operating Profile Model

## Purpose

Operating profiles tune governance ceremony and minimum evidence. They do not
select a command, set agent count, define completion scope, lower risk, change
quality mode, or expand user authority. The canonical policy is
`mcp/jstack/orchestration/policy.v1.json`; the pure resolver lives in
`mcp/jstack/orchestration/mode_integration.py` and the Team Composer applies
the result.

## Independent decision axes

| Axis | Question answered | Example |
| --- | --- | --- |
| Requested task mode | What action did the user authorize? | plan-only, diagnose-only, implement, fix, deploy |
| Operating mode | What physical execution topology may be used? | `/j-stack-dev`, `/jstack-subagents`, `/jstack-full-team` |
| Operating profile | What governance floor applies? | Solo, Professional, Enterprise |
| Scope strategy | How broadly may the authorized goal be completed? | `MINIMAL`, `BALANCED`, `COMPLETE` |
| Risk class | Which mandatory controls and independence floors apply? | trivial, normal, elevated, high, production |
| Quality level | Which existing output quality selector applies? | standard or enterprise where supported |
| Host contract | Which release-tested host capabilities are available? | Codex, Claude Code preview, generic MCP |

No axis is an alias for another. In particular, Enterprise does not mean Full
Team or deployment authority, and Solo does not mean low risk or permission to
skip mandatory evidence.

## Profiles

| Profile | Governance rank | Minimum controls | Intended ceremony |
| --- | ---: | --- | --- |
| Solo | 1 | Proportional verification | Minimal and low-friction |
| Professional | 2 | Independent review and quality assurance | Balanced commercial default |
| Enterprise | 3 | Professional controls plus policy conformance and risk-register evidence | Comprehensive and governed |

Omitted profile inputs resolve to Professional for compatible callers. This
default is independent of the legacy quality-level field.

## Monotonic resolution

The policy rule is `may-strengthen-never-weaken`:

```text
effective controls = profile floor
                   ∪ task/risk floors
                   ∪ repository/policy requirements
                   ∪ explicit user constraints
```

Controls may be added but a lower-ranked profile cannot remove a mandatory
risk control. Solo authentication still requires architecture, identity,
application-security, backend, and independent QA coverage. Production still
requires release, reliability, rollback, security, and independent assurance.

A stronger profile also cannot widen the goal, select `COMPLETE` scope,
increase write scope, permit more side effects, or authorize Git, release,
deployment, or production. Those remain separate user/host decisions.

## Delivery projection

The effective profile and Team Plan feed the same professional delivery
projection:

```text
plan → implement → review → QA → browser QA → security → evidence
```

Inapplicable phases are represented truthfully; profile affects required
evidence and independence, not phase authority. Only a separately authorized
mutating Team Plan may have one bounded Builder in the implementation phase.
Every other phase observes and reports. Candidate mutation makes
candidate-bound review, QA, browser, security, and evidence results stale.

## Compatibility and receipts

`jstack_plan` and `jstack_team_plan` accept the additive profile input. The
profile ID, effective controls, policy digest, delivery-pipeline digest,
project, repository, task mode, risk, scope, and Prompt/Context receipts are
bound downstream. Unsupported profiles fail closed. Older callers retain the
Professional default and the same public commands and authority model.

Profile changes are material: changing a selected or accepted profile
invalidates dependent composition, dispatch, delivery, and evidence receipts.
They do not modify the original Prompt Compilation authority envelope.

## Release boundary

Enterprise can require stronger release evidence but cannot execute a release.
Solo cannot bypass a release control required by production risk. Every
profile ultimately reaches the same `executionAuthorized=false` readiness
boundary and requires separate explicit action authority.

## Related documents

- [OPERATING_PROFILES.md](OPERATING_PROFILES.md)
- [TEAM_COMPOSER.md](TEAM_COMPOSER.md)
- [PROFESSIONAL_DELIVERY.md](PROFESSIONAL_DELIVERY.md)
- [RELEASE_DEPLOYMENT_UX.md](RELEASE_DEPLOYMENT_UX.md)
