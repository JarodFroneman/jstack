# Stage 8 — Low-Risk gstack Methodologies

## Status and authority

| Field | Value |
| --- | --- |
| Program stage | Stage 8 — Low-Risk gstack Methodologies |
| Recorded | 2026-08-26 |
| Advance-gate status | **PASS** — all seven methods behave as native JStack capabilities under JStack routing, authority, and evidence |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

`JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md` remains the authoritative
engineering specification. The attached Final Codex Master Prompt remains its
execution wrapper. This stage implements only the seven Class A methodology
adaptations named by Stage 8. It does not implement Stage 9 investigation
enforcement, a provider, browser execution, a new command, a new role, a new
authority model, or any release behavior.

## What was adapted

The implementation reviewed the immutable gstack snapshot at commit
`ad8400543cd9ce8d07641362db48d44a95417e33`, tree
`993294b0a09f5265d2d5af6d2fb8234ae2efe450`, version `1.69.0.0`, under MIT.
It re-expresses general methods as original structured JStack data; no gstack
prompt, persona, router, installer, updater, state engine, provider behavior,
or permission logic is copied or activated.

| JStack methodology capability | Reviewed source | JStack specialist | Existing base capabilities |
| --- | --- | --- | --- |
| Product Discovery | `office-hours/SKILL.md.tmpl` | Product Strategist | evidence-led handoff, product observability, workflow architecture |
| CEO and Product Review | `plan-ceo-review/SKILL.md.tmpl` | Product Strategist | evidence-led handoff, product observability, workflow architecture |
| Engineering Plan Review | `plan-eng-review/SKILL.md.tmpl` | Software Architect | workflow architecture |
| Design Plan Review | `plan-design-review/SKILL.md.tmpl` | Design Lead | accessibility, handoff, product observability, workflow architecture |
| Developer Experience Review | `plan-devex-review/SKILL.md.tmpl` | Developer Experience Lead | handoff, product observability, workflow architecture |
| Root-Cause Investigation | `investigate/SKILL.md.tmpl` | Root-Cause Investigator | codebase orientation, handoff, incident reliability |
| Engineering Retrospective | `retro/SKILL.md.tmpl` | Documentation and Handoff Writer | codebase orientation, handoff, workflow architecture |

The catalog records each method's narrow activation signals, allowed task and
operating modes, logical-specialist mapping, existing base capabilities,
bounded phases, required output sections, evidence contracts, stop conditions,
question policy, and constant non-authority contract.

## Canonical implementation

- `mcp/jstack/methodologies/catalog.v1.json` is the original, versioned
  methodology-capability catalog with immutable gstack provenance.
- `mcp/jstack/methodologies/registry.py` performs standard-library-only,
  closed validation and deterministic selection. It never invokes a model,
  provider, command, repository operation, or network request and retains only
  the normalized goal digest in its result.
- `mcp/jstack/schemas/methodology-catalog.v1.schema.json` and
  `mcp/jstack/schemas/methodology-plan.v1.schema.json` are closed published
  contracts.
- `mcp/jstack/orchestration/mode_integration.py` translates selected methods
  into existing Team Composer `requiredSpecialistIds` and
  `requiredEvidenceContractIds`; it does not create a second router.
- `mcp/jstack/jstack_mcp_server.py` returns the exact Methodology Plan through
  existing `jstack_plan`, `jstack_team_plan`, and capability-catalog output.
  Legacy skill recommendations no longer route these seven cases to upstream
  prompt names. No public MCP tool or slash command is added.

## Routing and receipt binding

The Stage 8 path is:

```text
approved Prompt Compilation + Context Readiness
                         |
                         v
 normalized goal + preserved task mode + existing operating mode
                         |
                         v
 deterministic JStack methodology selector
                         |
                         v
 required specialists + evidence -> existing Team Composer
                         |
                         v
 signed Team Plan receipt binds methodology catalog + selection digests
                         |
                         v
 existing dispatch and specialist-evidence gates
```

Engineering Plan Review is selected for `plan-only` work only when the goal
contains an engineering, architecture, implementation, code, or changed-
surface signal. Root-Cause Investigation is mandatory for `diagnose-only`.
The other methods require an explicit goal signal. This avoids blindly running
every review for every task. An empty selection is valid and must not be
inflated by the host.

The signed Team Plan receipt contains the methodology catalog version and
digest, selection digest, and selected method IDs. Dynamic dispatch recomputes
the selection from the exact goal, preserved task mode, and operating mode and
rejects catalog drift, goal drift, task-mode drift, changed selection, or an
altered Methodology Plan. The existing closed coordination packet remains
unchanged; its Team Plan receipt is the binding carrier, preserving the Stage
7 public contract.

## Permission and evidence boundary

Every record has these enforced properties:

- `authorityEffect: none`;
- canonical-role and task-mode authority are inherited, never raised;
- implementation and external-action authority are `none` for the method
  itself;
- provider invocation requires separate explicit authorization;
- persistence is `none`;
- raw prompts, hidden reasoning, source contents, and secrets are not stored;
- material questions remain owned by the existing Adaptive Context Gate with
  at most three per round and a recommended default;
- method evidence is added to the Team Plan but is never action authority.

A user-authorized `implement` or `fix` task may still proceed through the
existing scoped writer after planning. The selected review method does not
create that authority. A `plan-only`, `diagnose-only`, review, or research task
remains non-mutating. External research, browsers, model providers, Git,
release, deployment, production, and any external write stay behind their
existing JStack and host boundaries.

## Deliberately excluded upstream behavior

- large Markdown prompt bodies and persona wording;
- gstack command routing, hooks, state paths, global memory, or update logic;
- automatic web search, browsing, model selection, or provider fallback;
- automatic persistence, cross-project discovery, issues, messages, reports,
  social output, or personal productivity scoring;
- arbitrary universal plan-size limits, mandatory mockups, forced competitor
  research, or fixed questionnaires;
- the claim that review, QA, evidence, or readiness authorizes remediation;
- any upstream instruction that conflicts with JStack's proportional scope,
  task-mode preservation, privacy, evidence, or permission model.

## Stage boundary

Root-Cause Investigation in this stage is a routed methodology capability. It
requires symptom, reproduction, hypothesis, test, and conclusion evidence and
records a three-cycle escalation condition. This Stage 8 record did not itself
enforce remediation sequencing. Stage 9 now supplies that stronger
evidence-led dispatch gate and rejects random-fix loops; see
`ROOT_CAUSE_INVESTIGATION.md`.

Stage 10 reuses Product Discovery, CEO and Product Review, Design Plan Review,
and Developer Experience Review inside the existing Product Interface
capability family. It adds a bounded human-selected design-decision binding,
not another methodology catalog, intake gate, question owner, or authority;
see `PRODUCT_DESIGN_DEPARTMENT.md`.

## Verification and advance gate

Stage 8 verification must prove:

1. exactly seven immutable-provenance methodology records validate against
   the closed catalog schema;
2. selection is deterministic, bounded, digest-only, and proportional;
3. every selected method maps to an existing specialist, canonical role, and
   base capability without adding authority;
4. `plan-only` and `diagnose-only` preserve their non-mutating boundaries;
5. selected specialists and evidence flow through Team Composer rather than a
   second authority or router;
6. the signed receipt detects catalog, selection, goal, task-mode, operating-
   mode, and Methodology Plan tampering;
7. providers, persistence, upstream prompts, and hidden reasoning remain
   absent;
8. Dev, Subagents, and Full Team consume the result while Loop, Audit, and
   Evidence Builder remain separate;
9. the six commands, 59 canonical tools, 52 frozen aliases, existing 18 base
   capabilities, standard-library core, and published compatibility contracts
   remain intact; and
10. focused, full-regression, provenance, synchronization, boundary, schema,
    compile, and clean-diff gates pass together.

The local candidate passed:

- 8 focused Stage 8 tests covering the exact seven records, immutable source
  binding, deterministic and proportional selection, digest-only goal
  handling, schema/validator closure, specialist and evidence routing,
  plan-only and diagnosis-only boundaries, signed-receipt tamper rejection,
  direct-upstream-skill exclusion, documentation, and distribution parity;
- 121 focused Prompt Compiler, Context Readiness, Team Composer, capability,
  dynamic operating-mode, provenance, schema, synchronization, public-contract,
  and product-boundary tests;
- 82 installer, compatibility-router, and action-safety tests;
- the full 1,063-test unit and adversarial suite, with 12 declared
  optional/platform skips and zero failures; and
- compile, installed-plugin import, generated-artifact synchronization,
  alpha.9 contract compatibility, six-command/59-tool/52-alias product
  boundaries, standard-library-only core, and pinned 761-file/8-record gstack
  provenance checks.

The optional `jsonschema` package was unavailable in this local runtime, so its
single Stage 8 duplicate schema-library check skipped by design. Production
does not depend on that package: the standard-library registry performed the
closed semantic validation in every exercised path, while the published JSON
Schemas were included in inventory and compatibility checks.

**Advance-gate decision: PASS.** All seven Stage 8 methods now behave as
native JStack capabilities under JStack permissions. This local PASS did not
itself authorize a commit, push, release, deployment, installation, or any
other external action. Stage 9 was approved separately and remains subject to
its own advance gate.
