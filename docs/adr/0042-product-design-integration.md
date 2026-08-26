# ADR 0042: Product And Design Methods Extend The Product Interface System

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0023](0023-product-interface-system.md),
  [ADR 0024](0024-ui-reference-evidence-builder.md), and
  [ADR 0026](0026-product-ui-motion-intelligence.md)

## Context

gstack offers useful discovery, product challenge, design consultation,
alternatives, design review, and developer-experience methods. JStack already
has Product Interface contracts, evidence/reference handling, motion
intelligence, and finalization. Adding a separate design authority would create
conflicting precedence and allow exploration to rewrite production.

## Decision

Adapt selected product and design methods into JStack's existing Product
Interface capability family and specialist directory. Design precedence stays:
explicit user requirements, application design system, existing tokens and
components, accessibility requirements, approved reference evidence,
product/domain guidance, then fallback JStack guidance.

Exploration produces bounded alternatives and requires human selection before
implementation. It has no source-write, Git, or deployment authority. Selected
implementation uses authorized Builder roles, shared UI/motion contracts, and
fresh browser/runtime evidence when applicable.

The implementation adds no command or tool. The existing
`jstack_ui_contract` accepts an optional closed Product/Design decision. An
ordinary contract remains v1 and a reference-only contract remains v2; a
design-bound contract uses additive v3, or v4 when it also binds a reference.
The normalized decision stores the selected direction and digest-only approval
and source references, never raw approval text or hidden reasoning. It carries
`authorityEffect=none` and explicit false values for implementation, provider,
candidate-mutation, and production-mutation authority.

For material exploration, the host must display two or three coherent
alternatives and wait for explicit human selection or revision before any
implementation. The MCP validates the selection and receipt binding but cannot
intercept arbitrary host-native edits or independently prove the human's
identity. Existing task mode, readiness, Team Plan, and host permissions remain
the implementation authority.

Logical specialists may include Product Strategist, Design Lead, UX Designer,
Design Systems Engineer, UI Engineer, Motion Designer, Accessibility
Specialist, and Browser QA. They become physical agents only when the mode and
TeamPlan require it.

## Rejected Alternatives

- Install the upstream design system unchanged: rejected for contract and host
  mismatch.
- Add a second Product UI command: rejected as redundant routing.
- Let generated alternatives change source automatically: rejected as silent
  scope and authority expansion.

## Consequences

Product UI gains stronger methods without fragmenting design governance or
weakening existing evidence and motion gates.
