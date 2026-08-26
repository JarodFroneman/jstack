# JStack Deterministic Team Composer

## Stage and authority boundary

This document records the Stage 6 implementation at the immutable baselines
in `BASELINE.md`. The attached Unified Engineering OS specification remains
authoritative. The Team Composer is a pure JStack domain component: it does not
dispatch an agent, invoke a provider, read or write a repository, run a tool,
create a receipt, perform Git operations, or authorize an external action.

Stage 7 now connects `/j-stack-dev`, `/jstack-subagents`, and
`/jstack-full-team` to this component through the existing planning and
dispatch tools. The bridge, signed Team Plan, and coordination packet are
documented in `DYNAMIC_OPERATING_MODES.md`. Loop, Audit, and Evidence Builder
remain distinct workflows and do not consume the new packet in Stage 7.

Stage 8 adds a separate immutable-provenance methodology-capability catalog.
Its deterministic selector feeds required specialists and evidence into this
same Team Composer rather than creating another router. The exact catalog and
selection digests are bound into the signed Team Plan receipt. See
`LOW_RISK_METHODOLOGIES.md`.

Stage 9 keeps that same Team Plan and adds phase-specific dispatch slices when
Root-Cause Investigation is selected. The investigation slice contains only
the read-only investigator. A remediation slice exists only after the exact
passing specialist receipt establishes a cause on the unchanged candidate,
and it restores no authority beyond the original plan. Team Composer remains
the sole composition owner; see `ROOT_CAUSE_INVESTIGATION.md`.

Stage 10 also keeps that Team Plan. Product/Design specialists remain logical
function coverage; design exploration creates neither physical agents nor
mutation authority. The Product UI skill presents bounded alternatives for
human selection, and any later implementation still uses the Team
Composer-selected Builder under the original task mode and scopes. See
`PRODUCT_DESIGN_DEPARTMENT.md`.

## Canonical implementation

- `mcp/jstack/orchestration/policy.v1.json` is the versioned composition
  policy for modes, profiles, scope strategies, risk floors, and decision
  rules.
- `mcp/jstack/orchestration/team_composer.py` validates the policy and request,
  raises risk monotonically, selects logical specialists, resolves mandatory
  independence, minimizes physical agents, and emits the existing
  `jstack.team-plan.v1` contract.
- `mcp/jstack/schemas/team-composer-request.v1.schema.json` is the closed input
  contract.
- `mcp/jstack/schemas/team-composer-policy.v1.schema.json` is the closed policy
  contract.
- `mcp/jstack/schemas/unified-os-domain.v1.schema.json#TeamPlan` remains the
  output contract.

The policy is digest-bound to the exact Stage 5 specialist directory. A stale
directory or policy binding fails closed. The request binds the project,
repository fingerprint, effective policy, approved Prompt Compilation, and
Context Readiness. The output adds a digest of the exact normalized composition
input; it does not persist the normalized goal itself.

## Input and output semantics

The request represents the specification's inputs through:

- normalized goal and preserved requested task mode;
- inspected classifications, domains, changed surfaces, and repository
  signals;
- requested risk, operating profile, operating mode, and scope strategy;
- dependency-change and required-independence state;
- available providers and host capabilities;
- explicit specialists and effective organization-policy controls;
- bounded read/write scopes and context-token budget;
- Prompt Compiler, Context Readiness, project, repository, and policy digests.

The resulting Team Plan records:

- selected departments and specialists with canonical roles and capabilities;
- one non-overlapping primary source writer when implementation is authorized;
- physical-agent allocation that satisfies deterministic separation edges;
- read/write scopes, evidence, providers, selection reasons, and omissions;
- risk-resolution reasons, contradiction owner, and effective limits;
- constant non-authority invariants.

Specialists remain logical expertise. Multiple compatible specialists may be
assigned to one physical agent. Independent QA, security, quantitative,
architecture, or release assurance is assigned to a different physical agent
from the relevant writer or release actor. A provider's availability cannot
select expertise, grant authority, or substitute for evidence.

## Deterministic decision table

| Scenario | Minimum risk | Required material expertise |
| --- | --- | --- |
| Tiny CSS/copy/style | Trivial | Lead only, with focused UI evidence |
| Frontend feature | Normal | Frontend, Product Design, QA; Browser QA when the inspected surface is browser/web |
| Backend API | Normal | API Platform, QA |
| Authentication | High | Architecture, IAM, AppSec, Backend, QA |
| Security boundary | High | Architecture, AppSec, bounded Backend implementation, independent Security Audit, QA |
| Financial calculation | High | Architecture, Backend, Quant, independent Financial Review, Regression, QA |
| Data pipeline | Elevated | Architecture, Data, Database, Regression, QA |
| Infrastructure | Elevated | Architecture, Infrastructure, DevOps, Reliability, QA |
| Production release | Production | Architecture, DevOps, Release Engineering, Reliability, QA Lead, independent Release and Security Audit |

Dependency changes add Supply-Chain Security. Migrations and destructive data
operations add Database, recovery, regression, and independent security
controls. Accessibility, motion, and browser specialists are selected only
when those inspected surfaces are material.

## Preserved authority and scope rules

- Requested task mode is copied exactly into the Team Plan.
- Only `implement` or `fix` may contain source write scopes.
- A read-only operating mode cannot contain source write scopes.
- Exactly one selected specialist receives the bounded source write scope;
  selection does not raise the canonical role ceiling.
- `plan-only`, `diagnose-only`, review, audit, test, Git, release, deployment,
  production, and external-action task modes gain no source write scope from
  composition.
- `COMPLETE` scope requires a separate explicit broad-scope authorization bit.
- Solo may reduce ceremony but cannot lower a mandatory risk floor.
- A policy-forbidden specialist that is mandatory for risk causes a closed
  failure; the compiler does not silently weaken the team.
- A physical-agent, specialist, or context budget that cannot satisfy required
  expertise or independence causes a closed failure.
- A Team Plan has `authorityEffect: none`; evidence and readiness never
  authorize side effects.

## Stage 6 verification gate

`tests/test_team_composer.py` covers all required decision-table scenarios,
selected and omitted specialists, security work, deterministic output,
physical independence, task-mode preservation, profile monotonicity, policy
conflicts, context and agent budgets, provider non-authority, scope authority,
schema closure, stale bindings, tampering, distribution parity, and raw-goal
non-persistence.

**Advance-gate criterion:** a tiny CSS task selects one Lead and one physical
agent; high-risk and production tasks select their mandatory specialists and
independent assurance without receiving action authority. This criterion was
satisfied before Stage 7 integration began; the separate Stage 7 gate requires
Full Team to consume composition output instead of blindly dispatching a fixed
roster.
