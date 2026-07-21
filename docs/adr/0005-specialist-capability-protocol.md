# ADR 0005: Role-Bound Specialist Capability Protocol

- Status: Accepted
- Target release: 0.6.0
- Date: 2026-07-21

## Context

JStack already had five stable operating commands and an 11-role professional
team model. Adding one slash command per specialty would multiply entry points,
fragment permission policy, and make staffing harder to reason about. Keeping
only generic role prompts, however, left API, identity, incident, accessibility,
performance, agent-system, and similar work dependent on unversioned prose and
unvalidated specialist handoffs.

The Agency Agents repository provided useful specialist methods and handoff
patterns, but its complete agent collection, installer, personalities, and
prompt-level orchestration were not a compatible runtime or security model for
JStack.

## Decision

Add a strict versioned capability catalog inside JStack. Deterministically
route applicable packs to the already-selected core roles and require every
pack to use `permissionMode: inherit-role`. Bind the catalog and selection into
planning, dispatch, specialist result receipts, audit sessions, durable loop
contracts, and completion evidence.

Require specialist output to conform to a published structured result schema.
Accept only privacy-minimized telemetry metadata and derive its input/output
digests server-side. Validate all expected per-role receipts, write ownership,
and contradiction resolutions before issuing a team handoff receipt.

Adapt selected upstream ideas into JStack-native data and contracts at a pinned
commit under MIT, with explicit notices. Do not import the upstream runtime,
installer, roster, personalities, or permission behavior.

## Consequences

Positive consequences:

- the five command surface remains stable;
- specialization is deterministic, inspectable, versioned, and testable;
- role permissions remain the sole authority boundary;
- audit and loop evidence can prove which specialist contract was applied; and
- handoff completeness, staleness, tampering, and contradictions fail closed.

Costs and limitations:

- clients must preserve exact capability plans and emit structured results;
- adding or changing a pack is a protocol change that needs schema, routing,
  security, documentation, packaging, and adversarial review;
- session-local HMAC receipts do not prove semantic truth or resist compromise
  of the same operating-system account; and
- metadata minimization reduces exposure but does not make telemetry anonymous.

## Rejected alternatives

- A sixth “capability pack” slash command: it would make capability selection a
  competing operating mode instead of upgrading all five workflows.
- Importing the complete upstream agent collection: it would duplicate JStack's
  roster and bypass its permission, evidence, loop, and release boundaries.
- Free-form specialist handoffs only: they cannot be deterministically checked
  for required evidence, current state, routing, or permission consistency.
- Full raw tracing: it would retain unnecessary prompts, arguments, output, and
  potentially secrets for limited verification value.
