# JStack Dynamic Operating Modes

## Status and authority

| Field | Value |
| --- | --- |
| Program stage | Stage 7 — Dynamic Operating Modes |
| Recorded | 2026-08-26 |
| Advance-gate status | **PASS** — Full Team no longer blindly means a fixed roster |
| Candidate default | `preview` |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

The attached `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md` remains the
authoritative engineering specification and the attached Final Codex Master
Prompt remains its execution wrapper. This stage implements only the stated
Stage 7 objective: Dev, Subagents, and Full Team consume deterministic Team
Composer output, while Loop, Audit, and Evidence Builder remain separate
workflows.

This stage does not adopt an upstream control plane, import a gstack runtime,
change the six-command surface, create a new action authority, or implement
later-stage methodologies, providers, profiles, delivery pipelines, or release
behavior.

## Integration boundary

The Stage 7 path is:

```text
approved Prompt Compilation + Context Readiness
                         |
                         v
          existing jstack_plan / jstack_team_plan
                         |
                         v
        JStack-native mode-integration translation
                         |
                         v
           deterministic Team Composer TeamPlan
                         |
                         v
       signed plan + closed coordination packet
                         |
                         v
             existing jstack_dispatch_check
                         |
                         v
       host performs any separately authorized dispatch
```

`mcp/jstack/orchestration/mode_integration.py` is a pure translation layer. It
does not inspect repositories, invoke a model or provider, dispatch an agent,
write state, or authorize an action. The existing MCP adapter supplies verified
bindings and signs the returned Team Plan. The host remains responsible for
actual multi-agent dispatch, collection, and ordinary permission enforcement.

## Operating-mode behavior

| Existing mode | Team Composer behavior | Physical topology |
| --- | --- | --- |
| `/j-stack-dev` | Chooses the smallest competent logical team | Normally one accountable Lead; one independent checker only when a mandatory risk floor requires it |
| `/jstack-subagents` | Chooses the smallest competent specialist team | Normally two or three specialist agents; up to four only when required by risk and independence |
| `/jstack-full-team` | Covers every material function and independence boundary | Dynamic logical specialists grouped into the smallest safe physical allocation; never a fixed employee roster |

Logical specialist count, canonical-role count, and physical-agent count are
different quantities. Specialists inherit the maximum authority of one stable
canonical role. Compatible specialists may share a physical agent. A writer
and an independent reviewer, security auditor, QA owner, quantitative reviewer,
or release auditor remain separated when policy requires it.

The legacy `agents` array and eleven canonical roles remain an additive
compatibility projection for old callers. They are explicitly marked as not
the composition source of truth and cannot be used to dispatch or manufacture
missing evidence when a signed dynamic plan is present.

## Prompt, context, and scope binding

Dynamic dispatch is eligible only when all of the following match:

- an explicitly approved Stage B Prompt Compiler result, bound to the exact
  displayed rendered-prompt digest;
- its Context Readiness receipt and normalized brief;
- workflow mode and preserved requested task mode;
- project digest and current Git repository fingerprint;
- Team Composer policy, specialist directory, compiler, and prompt-template
  bindings; and
- the complete signed Team Plan and byte-equivalent closed coordination
  packet returned by JStack.

For `implement` and `fix`, one source-labelled `authorized_write_scopes` fact
must contain a bounded repository-relative path or JSON string array derived
from the explicit goal or inspected task boundary. Root, absolute, traversing,
untrusted, or invented scopes fail closed. Exactly one logical assignment may
receive that source scope. A Team Plan and readiness receipt have
`authorityEffect: none`; neither can authorize a repository, Git, provider,
release, deployment, production, or external action.

## Feature modes and rollback

`JSTACK_UNIFIED_OS_MODE` is a closed deployment control:

- `disabled`: preserve the legacy planning and fixed compatibility behavior;
- `shadow`: compute a non-dispatchable comparison without changing execution;
- `preview`: return the dynamic plan visibly; only an approved, fully bound
  plan is dispatchable; and
- `enforced`: fail closed unless approved Prompt Compilation, Context
  Readiness, project, repository, policy, packet, and scope bindings all pass.

Any other value is rejected. The Beta candidate default is `preview`, making
the migration visible and reversible while retaining the legacy path through
`disabled`. Moving a release default to `enforced` requires a later explicit
release decision; this stage does not make that decision.

Stage 14 owns user-selectable Solo, Professional, and Enterprise profiles.
Until that stage supplies an explicit profile input, the bridge uses the
specification's Professional governance profile as a conservative internal
default. That temporary default may strengthen governance but cannot weaken a
risk floor or expand authority.

## Dynamic evidence handoff

The signed Team Plan produces `jstack.team-coordination.v2`, containing ordered
logical assignments, canonical roles, physical-agent mappings, exact
capabilities, read/write scopes, separation requirements, evidence contracts,
stop conditions, and immutable bindings. Unknown fields and altered or
regenerated packets are rejected.

The existing specialist-result tools accept an additive dynamic path:

1. every logical specialist returns the existing bounded result and
   metadata-only telemetry objects;
2. the Lead supplies the exact Team Plan receipt, logical specialist ID,
   physical-agent ID, canonical role, capabilities, and scope;
3. JStack emits a versioned logical-specialist receipt; and
4. handoff succeeds only when every ordered assignment is present exactly once
   and its candidate, plan, scope, capability, role, and physical mapping still
   match.

Missing, duplicate, stale, tampered, scope-drifted, capability-drifted,
permission-unsafe, or contradictory receipts fail closed. Raw prompts,
messages, source contents, command or model output, tool arguments, and secrets
remain forbidden in telemetry.

## Preserved workflows and limitations

- `/jstack-loop` remains the existing persistent orchestration workflow. Stage
  7 does not inject the new Team Plan or v2 handoff receipt into frozen Loop
  state without a later explicit versioned binding.
- `/jstack-audit` remains independent, read-only assurance. Audit findings do
  not become remediation authority.
- `/jstack-evidence-builder` remains the private, reference-evidence workflow.
  Reference evidence does not become implementation authority.
- Artifact-only projects may receive descriptive team planning and direct
  artifact evidence, but cannot receive Git-bound dynamic certification.
- JStack can validate its MCP tools and receipts. It cannot intercept arbitrary
  native host actions that bypass those tools, and it does not claim otherwise.
- The public surface remains six commands, 59 canonical tools, and 52 frozen
  legacy aliases. No new public tool is added in Stage 7.

## Verification and advance gate

Stage 7 verification must prove:

1. Dev, Subagents, and Full Team all consume the same deterministic composer;
2. a tiny task remains tiny, while high-risk work retains mandatory expertise
   and physical independence;
3. Full Team dispatch follows selected logical assignments rather than the
   fixed eleven-role compatibility projection;
4. task mode, explicit non-goals, exact scope, and user action authority are
   preserved;
5. prompt, context, project, repository, policy, plan, and packet drift are
   rejected;
6. every logical specialist is independently receipted and reconciled;
7. disabled, shadow, preview, and enforced behavior is closed and reversible;
8. Loop, Audit, Evidence Builder, tool names, aliases, installer behavior, and
   generated distribution copies remain compatible; and
9. provenance, synchronization, schema, boundary, compile, focused, and full
   regression gates pass together.

The same local candidate passed:

- 12 focused Stage 7 tests, including dynamic planning, packet tampering,
  repository drift, task-mode preservation, exact source scope, dynamic
  logical-specialist receipts, workflow separation, rollback modes, and
  distribution parity;
- 100 focused cross-feature Prompt Compiler, Context Readiness, capability,
  Product Interface, and legacy planning tests;
- 77 installer and compatibility-router tests;
- 43 architecture, domain, organization, provenance, synchronization, public
  contract, and product-boundary tests;
- the full 1,055-test unit and adversarial suite, with 11 declared
  optional/platform skips; and
- compile, generated-artifact synchronization, alpha.9 contract
  compatibility, six-command/59-tool/52-alias product boundaries, pinned
  gstack provenance, corpus-lock, and clean-diff checks.

The first local full-suite attempt was invalidated because a compile check was
run without CI's external `PYTHONPYCACHEPREFIX`, creating untracked bytecode in
sealed evaluation fixture directories. Only those generated `.pyc` files were
removed. All 16 affected corpus tests then passed, and the complete 1,055-test
suite passed when repeated with the CI-equivalent external bytecode cache.

**Advance-gate decision: PASS.** Stage 7 may advance to Stage 8 only under a
separate implementation step. This local PASS does not authorize a commit,
release, deployment, installation, or any other external action.
