# ADR 0036: Adapt gstack Methodology Into JStack-Native Capabilities

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Depends on: [ADR 0035](0035-upstream-provenance.md)

## Context

gstack's product, design, engineering-review, investigation, QA, security, and
retrospective methods contain useful professional practices. Its skills also
embed host assumptions, large prompt bodies, control flow, side effects, and
permissions that do not map directly to JStack.

## Decision

Class A material is re-expressed as original, bounded JStack capability data:
purpose, activation, method steps, applicable roles, required evidence, stop
conditions, provenance, and risk constraints. Adapt the method, not the
upstream persona or control plane.

Capabilities inherit canonical-role authority, do not dispatch agents, do not
invoke providers implicitly, and cannot override Prompt Compilation, Context
Readiness, scope, policy, or action gates. Large Markdown prompts are not the
canonical structured representation. Upstream wording is copied only when
necessary, license-compatible, attributed, and reviewed.

Mixed upstream workflows are split: methodology becomes Class A, runtime work
becomes a Class B provider request, control-plane behavior is Class C and not
imported, and unsuitable material remains Class D.

## Rejected Alternatives

- Install upstream skills unchanged: rejected for host and authority mismatch.
- Translate every skill automatically: rejected because disposition and risk
  require human-reviewed engineering decisions.
- Copy giant prompts into commands: rejected as brittle duplication.

## Consequences

JStack gains maintainable methods at the cost of deliberate adaptation and
evaluation. Stage 8 starts with low-risk methods before broader rollout.
