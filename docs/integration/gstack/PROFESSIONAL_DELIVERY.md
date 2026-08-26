# Stage 13 — Professional Delivery Pipeline

## Status and authority

| Item | Value |
| --- | --- |
| Objective | Project one approved Team Plan into `plan → implement → review → QA → browser QA → security → evidence` |
| Architecture | Existing JStack Team Composer and authority kernel remain authoritative |
| Authority effect | None; the pipeline neither dispatches nor authorizes work |
| Advance gate | **PASS** — Solo, Professional, and Enterprise use `jstack-authority-kernel-v1` |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

`mcp/jstack/orchestration/delivery.py` implements an original deterministic
projection, not another scheduler. The existing Team Plan supplies the exact
specialists, physical agents, canonical roles, scopes, evidence contracts,
task mode, risk, profile, project, and repository bindings. The delivery
projection orders those facts for host presentation and evidence
reconciliation.

## Phase contract

| Phase | Candidate-bound | May observe source mutation | Purpose |
| --- | --- | --- | --- |
| Plan | No | No | Confirm scope, authority, risks, and acceptance evidence |
| Implement | Yes | Yes, only for the exact Team Plan writer | Produce the bounded candidate delta |
| Review | Yes | No | Independent correctness, architecture, compatibility, and scope review |
| QA | Yes | No | Proportional repeatable verification |
| Browser QA | Yes | No | Applicable user-facing runtime evidence |
| Security | Yes | No | Applicable security and supply-chain evidence |
| Evidence | Yes | No | Reconcile current evidence, blockers, and unproven claims |

Every phase has `authorityEffect: none`. Non-mutating task modes cannot contain
a writer. Mutating work requires exactly one writer whose write scope already
exists in the signed Team Plan. Review, QA, browser QA, and security never gain
remediation authority.

Any candidate change makes all candidate-bound phase evidence stale. Plan
evidence remains usable because it is bound to the Team Plan rather than a
candidate delta. `evaluate_delivery_evidence` is a pure evaluator: it does not
persist state, execute providers, call models, write source, or perform Git or
external actions.

## Integration decision and discrepancy

The specification asks for a coherent professional pipeline. JStack already
has Program and Loop orchestration, so Stage 13 does not create a duplicate
control plane or public MCP tool. Instead, `jstack_plan` and
`jstack_team_plan` return `professionalDeliveryPipeline`, and the signed
Unified Team receipt binds its digest and authority-architecture ID. Dispatch
recomputes the projection from the exact Team Plan and rejects drift.

This design preserves the specification's phase order while treating it as an
evidence contract that a host or existing Program may enact only under normal
JStack permissions.

## Files, tests, and compatibility

Canonical artifacts are:

- `mcp/jstack/orchestration/delivery.py`;
- `mcp/jstack/schemas/delivery-pipeline.v1.schema.json`;
- `mcp/jstack/schemas/delivery-phase-evidence.v1.schema.json`;
- `mcp/jstack/jstack_mcp_server.py`; and
- `tests/test_delivery_profiles.py`.

Focused tests cover phase order, the sole mutation phase, schema validity,
candidate invalidation, profile architecture parity, tampering, and evidence
authority escalation. The change is additive: six commands, 60 canonical MCP
tools, and 52 frozen aliases remain unchanged.

No Stage 13 contract authorizes implementation, Git, release, deployment,
installation, or production mutation.
