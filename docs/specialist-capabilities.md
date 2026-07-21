# JStack Specialist Capability System

JStack v0.6 adds task-specific capability routing inside the five existing
commands. It is not a sixth command and it is not a second roster of agents.
The core role still determines accountability, tools, edit permission, and file
scope; the capability plan adds a bounded method, required evidence, stop
conditions, audit domains, and loop controls for that role's current task.

## Design goals

- Make an Architect working on an API contract behave differently from an
  Architect investigating an incident, without inventing a new permanent role.
- Turn specialist prose into a versioned, machine-validated evidence contract.
- Detect missing, stale, contradictory, or permission-violating handoffs before
  the Lead Engineer synthesizes them.
- Retain useful run metadata without retaining prompts, messages, tool
  arguments, model output, or secret values.
- Strengthen the existing audit and loop contracts without weakening their
  policy floors or creating new authority.

## Source of truth

The canonical registry is
`mcp/jstack/capabilities/catalog.v1.json`. Its loader in
`mcp/jstack/capabilities/registry.py` rejects unknown fields, duplicate IDs,
unknown roles, invalid regular expressions, unsafe source paths, and every
permission mode except `inherit-role`. The catalog and each selection receive
canonical SHA-256 digests.

The initial catalog contains 14 capability packs:

| Capability | Main purpose |
| --- | --- |
| `evidence-led-handoff` | Scope, evidence, verification, blockers, and residual-risk handoff |
| `minimal-change` | Smallest defensible patch and diff-scope control |
| `codebase-orientation` | Repository maps, execution traces, and uncertainty tracking |
| `developer-tooling` | Command, packaging, compatibility, and developer-experience contracts |
| `agent-systems` | Agent boundaries, schemas, failure paths, and trace metadata |
| `workflow-architecture` | State transitions, retries, cancellation, recovery, and ownership |
| `api-platform` | API contracts, error models, versioning, and compatibility |
| `database-reliability` | Data invariants, migrations, rollback, and recovery |
| `incident-reliability` | Operational signals, mitigation, rollback, and follow-up |
| `identity-access` | Authentication, authorization, sessions, secrets, and least privilege |
| `accessibility-assurance` | Automated and manual accessibility evidence |
| `performance-engineering` | Reproducible baselines, percentiles, budgets, and comparisons |
| `ai-code-security` | Model/tool trust boundaries, prompt injection, secrets, and negative tests |
| `compliance-assurance` | Technical control evidence, gaps, remediation, and residual risk |

## Deterministic routing

`jstack_plan` and `jstack_team_plan` classify the goal, select the existing core
roles, and then route capabilities from the same normalized goal and risk
classes. Routing uses catalog priority, default-role rules, bounded pattern
matches, and optional explicit capability IDs. It is deterministic for the same
catalog and inputs, preserves catalog order in its assignments, and limits each
role to four packs.

Explicit capability IDs are constraints, not an escape hatch. An unknown ID or
an ID not allowed for any selected role fails closed. The resulting
`capabilityPlan` includes:

- catalog version and digest;
- selection and goal digests;
- exact role-to-capability assignments;
- required evidence kinds and stop conditions;
- strengthened audit domains and loop controls; and
- the invariant that a capability never expands role permissions.

`jstack_dispatch_check` recomputes the plan. It rejects missing, reordered, or
extra capability assignments, role changes, write elevation, scope overlap, and
a coordination packet that does not contain the actual capability plan.

## Structured result and handoff path

After work, each selected role submits one `jstack_specialist_result` payload.
The result must conform to `jstack.specialist.result.v1` and contain its scope,
typed evidence, findings or changes, blockers, residual risk, skipped checks,
and recommended next action. Every evidence kind required by the role's routed
capabilities must be present. Read-only roles cannot report changes; Builder and
Documentation changes must remain inside their assigned scopes.

The server recomputes routing, validates the result and telemetry, takes a
stable Git subject before and after validation, and issues a session-local
specialist result receipt. That receipt binds the goal digest, complete team,
role, exact capabilities, catalog and selection digests, policy, JStack
version, Git HEAD, workspace fingerprint, structured result digest, and
telemetry digest.

The Lead then calls `jstack_specialist_handoff_check` with the expected agents
from the plan and all result receipts. It rejects:

- missing or duplicate roles and receipts;
- invalid signatures or receipts from another server session;
- stale Git, policy, tool-version, catalog, selection, goal, team, or result
  bindings;
- results that are blocked, failed, or missing required evidence;
- changes by read-only roles or overlapping change ownership; and
- contradictory findings sharing a resolution key.

The Lead may resolve a contradiction only with a structured decision,
rationale, and evidence references. A signed specialist handoff receipt is
issued only after every check passes. The receipt proves validated structure
and binding, not that a model-authored claim is semantically true.

Published schemas live at:

- `mcp/jstack/schemas/capability-catalog.v1.schema.json`
- `mcp/jstack/schemas/specialist-result.v1.schema.json`
- `mcp/jstack/schemas/specialist-telemetry.v1.schema.json`

Use MCP `tools/list` for the authoritative call schemas.

## Privacy-safe telemetry

`jstack.specialist.telemetry.v1` permits bounded execution metadata: run,
trace, and span identifiers; timestamps and derived duration; status; tool
name, status, and a reference to submitted evidence; and optional token counts.
The server derives input and output digests from the normalized capability
context and structured result.

`rawContentStored` must be `false`. Raw prompts, chat messages, tool arguments,
model outputs, hidden reasoning, and arbitrary logs have no schema fields;
recognized raw-content keys and secret-like values are rejected. Callers must
not encode raw content into metadata fields. This is data minimization, not
anonymity: identifiers,
timing, counts, tool names, and evidence references can still be operationally
sensitive and should receive the same local-access protection as other JStack
evidence.

## Existing command integration

- `/j-stack-dev` routes capabilities to the Lead and validates the Lead's own
  structured result; it still spawns no subagents.
- `/jstack-subagents` routes the smallest approved specialist team and requires
  one current receipt per selected role before synthesis.
- `/jstack-full-team` applies exact capabilities across the 11-role roster and
  validates the controlled-wave handoff.
- `/jstack-audit` accepts a bounded focus or explicit IDs for its read-only
  Reviewer, QA, and Security roles. Capability audit domains may add required
  coverage but can never remove profile, control-catalog, or policy domains;
  finalization rejects catalog drift.
- `/jstack-loop` stores a `capabilityContract` in goal readiness, durable state,
  revisions, and completion receipts. Smart-subagent and full-team checkpoints
  and finalization require a current handoff receipt matching that contract and
  Git state. Changing explicit capabilities is a material revision, and current
  routing drift stops further checkpoints until an approved revision.

## Authority and assurance limits

Capabilities do not spawn agents, grant tools, authorize filesystem access,
widen write scope, override policy, or permit commit, push, merge, deploy,
release, or production mutation. JStack validates contracts and evidence; the
host performs agent execution, and a human retains release authority.

This upgrade moves JStack closer to a professional development control plane by
making specialization repeatable and handoffs auditable. Professional or
production readiness still depends on project-specific tests, independent
review, security controls, deployment safeguards, observability, qualified
human judgment, and the limits described in `SECURITY.md`.

## Provenance

The catalog adapts selected engineering, testing, security, and handoff ideas
from `msitarzewski/agency-agents` at pinned commit
`459dce837db3bdfdc4763d3fefd1fd854e73c8f1`, under the MIT License. JStack did
not import its agent roster, personality prompts, installer, orchestration
runtime, or permission model. Exact adapted source paths and the upstream
license notice are recorded in `THIRD_PARTY_NOTICES.md`.
That notice is also mirrored into the installable MCP and umbrella-plugin
payloads.
