# JStack × gstack Stage 0 Baseline

## Status

| Field | Value |
| --- | --- |
| Program stage | Stage 0 — Baseline & Reproducibility |
| Recorded | 2026-08-26 |
| Advance-gate status | **PASS** |
| JStack subject | `JarodFroneman/jstack` `main` at `49cf545d940c43b394ea35ed78b5ab5742d7bcf7` |
| gstack subject | `garrytan/gstack` `main` at `ad8400543cd9ce8d07641362db48d44a95417e33` |
| Change class | Documentation-only baseline |

Stage 0 establishes the source, architecture, test, trust, compatibility, and
provenance baseline required by the JStack × gstack Unified AI Software
Engineering Operating System specification. It does not adopt gstack, install
gstack dependencies, change a JStack runtime contract, begin Stage 1, or
authorize Git, release, deployment, production, or other external actions.

## Specification authority and execution boundary

The attached `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md` remains the
authoritative engineering specification. The attached Final Codex Master
Prompt is its execution wrapper. This baseline preserves their primary
architectural decision:

> JStack is the kernel. gstack is a pinned methodology and optional provider
> source operating beneath JStack authority.

The following hashes bind the exact inputs reviewed for this stage without
copying their contents into receipts or telemetry:

| Input | SHA-256 |
| --- | --- |
| `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md` | `00e47070f78be1d10488ff89d001152fcd5827ddcd4718a1cd0d163625a33a2a` |
| Final Codex Master Prompt | `e6f3af49b85a96e321f4445d0f710bfcc39de5bd700ab1e3289bfb6a63842b16` |

Non-negotiable boundaries for every later stage are unchanged:

- one JStack authority, risk router, task state, evidence model, audit
  authority, and release decision;
- operating modes remain distinct from specialists, canonical roles,
  capabilities, providers, and physical agents;
- a methodology, persona, specialist, or provider cannot expand its own
  authority;
- QA, review, audit, security findings, readiness, and evidence never
  authorize remediation, Git writes, release, or deployment by themselves;
- optional runtimes remain optional and must return `UNAVAILABLE` or
  `UNSUPPORTED` instead of fabricating equivalent success;
- existing JStack risk floors, user authority, compatibility, and evidence
  gates may be strengthened but not silently weakened.

## Immutable source snapshots

Both working trees were inspected in isolated clean clones. Remote `main` was
rechecked immediately before this document was written and still resolved to
the recorded commit in each repository.

| Property | JStack | gstack |
| --- | --- | --- |
| Origin | `https://github.com/JarodFroneman/jstack.git` | `https://github.com/garrytan/gstack.git` |
| Branch | `main` | `main` |
| Commit | `49cf545d940c43b394ea35ed78b5ab5742d7bcf7` | `ad8400543cd9ce8d07641362db48d44a95417e33` |
| Tree | `0afa6b60047de246fc699ce098d6a8a587cac227` | `993294b0a09f5265d2d5af6d2fb8234ae2efe450` |
| Commit time | `2026-08-24T23:15:43+02:00` | `2026-08-24T08:55:58-07:00` |
| Version | `0.10.0-beta.6.2` | `VERSION=1.69.0.0`; package `1.69.0` |
| Tracked files | 665 | 1,364 |
| Tracked bytes | 12,203,700 | 29,496,620 |
| License | MIT, Jarod Froneman | MIT, Garry Tan |
| License SHA-256 | `d20c1ddeaea7119fa98a20698dd6de8071e35f7ecc4d2e74717e935a0a164968` | `e56fbb5b3d95756f3fa1cfefa24732ec79f18ece1ad08a4e79e00df57e8b198c` |

JStack's Proof Plane tests also require the exact annotated
`v0.10.0-beta.1` tag. The remote tag object is
`30e0a762a9ab1216a4d8b047705dd569ac4dd5e3`; its peeled commit is the expected
`7c38496febbd6aa60b51e119287e92d63a9f32ca`. The tag was fetched into the
inspection clone without modifying tracked source.

The ordinary shared JStack checkout was intentionally not used because it was
behind `origin/main` and contained unrelated user work. No user change was
cleaned, reset, overwritten, or included in this baseline.

## Reproduction environment

| Component | Observed value |
| --- | --- |
| Host | macOS 27.0 build `26A5416b`, arm64 |
| Python | 3.13.14 |
| Git | 2.54.0, Apple Git-157 |
| Node.js | 24.18.0 |
| Bun | unavailable |
| JStack test-only `jsonschema` | unavailable |

JStack CI supports Python 3.9 and 3.12 on Linux, macOS, and Windows, uses
Node.js 22, installs `jsonschema==4.23.0` for schema-validation tests, and
checks out full history so the annotated Beta.1 boundary is available. The
local run used a private mode-0700 temporary root under the current user.
Proof Plane correctly rejects `/private/tmp` because that ancestor is
world-writable.

gstack declares Bun `>=1.0.0`; its current free-test CI pins Bun 1.3.13 and
installs Playwright Chromium plus Linux display dependencies. No dependency
installation, setup script, generated host output, browser daemon, auto-update,
or gstack test execution occurred in Stage 0.

## JStack architecture map

### Product and source boundaries

- `README.md`, `ARCHITECTURE.md`, and `SECURITY.md` describe an independent,
  standard-library JStack product. `README.md` currently treats upstream
  gstack as optional extra skills, not a runtime dependency.
- `mcp/jstack/jstack_mcp_server.py` is the canonical MCP server and currently
  contains 28,353 lines. New integration logic must not increase this
  concentration risk.
- Coherent existing domains already live under `mcp/jstack/audit/`,
  `mcp/jstack/capabilities/`, `mcp/jstack/context_readiness/`,
  `mcp/jstack/launch/`, `mcp/jstack/loop/`, `mcp/jstack/program/`,
  `mcp/jstack/prompt_compiler/`, and `mcp/jstack/ui/`.
- Contracts live under `mcp/jstack/schemas/`. Canonical prompts live in
  `prompts/`; canonical workflow and Product Interface skills live in
  `skills/`.
- `scripts/sync_artifacts.py` owns generated copies under `plugin/` and
  `plugins/`. Generated files are mirrors, not independent edit targets.

### Operating modes and commands

The product exposes exactly six command prompts:

1. `/j-stack-dev`
2. `/jstack-subagents`
3. `/jstack-full-team`
4. `/jstack-loop`
5. `/jstack-audit`
6. `/jstack-evidence-builder`

These are operating modes or bounded workflows. Product Interface is an
automatic capability family, not another execution authority.

### MCP surface and compatibility

- JStack exposes 59 canonical `jstack_*` tools.
- The 52-tool alpha.9 surface remains frozen, with 52 legacy `gstack_*`
  aliases for compatibility.
- Seven additive tools are canonical-only: Prompt Compiler plus the six
  Product Interface reference, candidate, and motion tools.
- `scripts/check_contract_compatibility.py` and
  `scripts/check_product_boundaries.py` enforce these boundaries.

The legacy `gstack_*` spelling is a compatibility alias inside JStack. It is
not evidence that the upstream `garrytan/gstack` runtime is already integrated.

### Current roles, teams, and capabilities

`AGENT_ROSTER` in `mcp/jstack/jstack_mcp_server.py` defines 11 canonical
roles: Lead, Architect, Investigator, Builder, Reviewer, QA, Security, DevOps,
Product, Quant, and Documentation. `choose_agent_team` currently implements:

- single Lead;
- Lead plus a bounded selected specialist set; and
- explicit Full Team as the fixed complete 11-role roster.

The capability catalog at `mcp/jstack/capabilities/catalog.v1.json` is version
1.1.0 and contains 18 role-bound capability packs:

- `evidence-led-handoff`, `minimal-change`, `codebase-orientation`,
  `developer-tooling`, `agent-systems`, and `workflow-architecture`;
- `api-platform`, `database-reliability`, `incident-reliability`, and
  `identity-access`;
- `accessibility-assurance`, `performance-engineering`, `ai-code-security`,
  and `compliance-assurance`;
- `web-launch-assurance`, `email-deliverability`,
  `product-observability`, and `privacy-legal-evidence`.

JStack has role/capability selection and handoff receipts, but it does not yet
have explicit first-class contracts for `Specialist`, `Department`,
`OperatingProfile`, `ScopeStrategy`, `Provider`, `EvidenceContract`, or the
target `TeamPlan`. Explicit Full Team is not yet dynamically composed.

### Existing gates and stateful workflows

- Prompt Compiler provides Stage A intent normalization, Stage B
  repository-grounded compilation, visible final-prompt approval, and a
  receipt bound to the exact normalized brief.
- Adaptive Context and Goal Readiness already separate facts, assumptions,
  unknowns, recommended defaults, task mode, and user authority. They should
  be extended rather than duplicated.
- Loop supplies bounded durable goal execution, one checkout lease, circuit
  breakers, checkpoints, invalidation, recovery, and completion receipts.
- Program supplies dependency-graph orchestration, child-goal proof,
  human/external gates, revision, invalidation, and integrated final evidence.
- Audit is a separate read-only assurance system with versioned report and
  evidence contracts.
- Product Interface already has design-system, reference, candidate, motion
  specification, reduced-motion, and motion-evidence gates under
  `mcp/jstack/ui/` and `skills/product-ui-design/SKILL.md`.
- Launch and release-readiness receipts remain non-authorizing. Installer and
  release paths are transactional and rollback-aware.

Loop, Program, Product Interface, reference evidence, prompt compilation,
context readiness, and mastery state use private project-scoped locations
under `~/.jstack`. Loop and Program use atomic writes, private directories,
bounded readers, lock/lease semantics, and symlink rejection. A future gstack
adapter must not introduce a second durable task or authority state.

### Current baseline limitation discovered during intake

Prompt Compiler permits a 12,000-character `normalizedGoal`, but a requirement
statement is normalized to 1,000 characters. When a caller supplies the
reserved `user-goal` requirement for a goal longer than 1,000 characters,
`mcp/jstack/prompt_compiler/protocol.py` truncates the requirement and then
requires exact equality with the untruncated Stage A goal. The result is a
fail-closed digest/binding rejection. Stage 0 worked around this by compiling a
bounded, semantically equivalent execution request while retaining both
authoritative attachment digests, constraints, task mode, and authority.

This is a verified pre-existing defect. It is not fixed by this documentation
stage and must not be confused with a Unified OS design decision.

## gstack architecture map

### What the repository is

gstack is a Bun/TypeScript, Markdown-skill, CLI, browser, and workflow system
that presents a virtual software-company experience across supported coding
hosts. It is not merely a prompt collection and is not a single runtime
library. Its repository contains:

- 56 canonical `SKILL.md.tmpl` skill templates;
- generated `SKILL.md` files that must not be edited independently;
- Bun/TypeScript CLIs, scripts, setup and update behavior;
- a long-lived Playwright/Chromium browser daemon;
- QA, product, design, investigation, security, review, shipping, deployment,
  document, iOS, memory, and benchmarking surfaces;
- project and global state beneath `.gstack` and `~/.gstack`;
- 1,364 tracked files and 470 files under `test/`.

The README describes 23 specialists and eight power tools. That product
description is not a schema and must not be equated to the 56 skill templates,
JStack canonical roles, physical agents, or future JStack specialists.

### Generation and supported hosts

Canonical skill content is authored in `.tmpl` files and generated for host
layouts. `hosts/index.ts` registers ten host configurations: Claude, Codex,
Factory, Kiro, OpenCode, Slate, Cursor, OpenClaw, Hermes, and GBrain.

Codex output support proves that gstack can generate Codex-shaped skills. It
does not provide JStack-native schemas, receipts, permissions, state,
capability routing, MCP semantics, or evidence binding. Direct installation is
therefore not an integration strategy.

### Browser/runtime provider

`ARCHITECTURE.md` and `browse/src/` define a persistent Chromium daemon that:

- starts on first use and preserves tabs, cookies, and browser state;
- exposes a loopback HTTP command surface with a bearer token;
- records project state in `.gstack/browse.json` and logs under `.gstack`;
- supports an explicitly separate scoped tunnel listener;
- includes prompt-injection filtering, output sanitization, denial logs,
  bounded security telemetry, and egress receipts;
- depends on Bun/Node behavior, Playwright, Chromium, and OS-specific setup.

gstack explicitly does not use MCP for this browser. A JStack integration
therefore needs an optional, versioned provider adapter with declared
capabilities, permission checks, data-flow controls, evidence conversion,
timeouts, cancellation, and an unavailable state. The provider cannot become
an orchestrator or evidence authority.

### Methodologies with potential value

The most relevant methodology sources for later disposition are:

- product interrogation and office hours;
- CEO/product, engineering, design, and developer-experience review;
- design consultation, exploration, and review;
- root-cause investigation;
- real-browser QA and report-only QA;
- practical review and documentation;
- security/CSO review and prompt-injection defenses;
- release, canary, deployment, and rollback ergonomics;
- retrospective, learning, and context workflows.

These are candidates for independent JStack adaptation or bounded provider
use. They are not approved capabilities merely because they exist upstream.

### Direct side effects and authority conflicts

Several upstream workflows intentionally combine responsibilities that JStack
keeps separate:

- `/qa` and `/design-review` may edit source and create commits after finding
  defects;
- `/ship` may modify release metadata, commit, push, and open a pull request;
- `/land-and-deploy` may merge, deploy, monitor, and revert;
- `/spec` may persist state, file issues, or spawn execution;
- `/cso` may invoke tools, inspect external sources, and write reports;
- continuous checkpoint mode can create local commits, with optional pushes;
- setup may register hooks, generated skills, SessionStart checks, and update
  behavior;
- optional telemetry, tunnels, model providers, memory sync, Supabase/GBrain,
  remote code intelligence, and device QA can send data off-machine.

These surfaces cannot be used unchanged. JStack must split observation from
remediation, readiness from authorization, methodology from execution, and
provider evidence from final assurance.

### State, maintenance, and dependencies

gstack can write both repository-local and global state, install host skills,
register hooks, retain browser cookies/tabs, keep analytics and security logs,
and optionally synchronize memory. Its default Claude team experience includes
a throttled SessionStart update check, and `auto_upgrade` can be enabled.

Enterprise provenance cannot rely on a silently moving upstream. Every adopted
or adapted source must be pinned to an immutable commit, classified, reviewed,
licensed, and updated through an explicit JStack synchronization lifecycle.

Runtime dependencies include Playwright, `@ngrok/ngrok`,
`@huggingface/transformers`, `cross-spawn`, `diff`, `marked`, `html-to-docx`,
and `socks`; development/evaluation surfaces include Anthropic SDKs and xterm.
None may become an unconditional JStack core dependency without a later
approved architecture decision and evidence that native or existing JStack
facilities are insufficient.

## Initial trust and side-effect map

This is a Stage 0 boundary map, not the Stage 1 disposition matrix.

| Upstream surface | Stage 0 trust | Potential relationship | Required JStack boundary |
| --- | --- | --- | --- |
| Markdown skill methodology | Pinned external data | Class A candidate | Original JStack adaptation; canonical role and risk-floor enforcement |
| Browser/Playwright runtime | Optional executable provider | Class B candidate | No orchestration authority; scoped permission, egress, evidence, timeout, and unavailable contracts |
| QA/design review methods | Mixed observation/remediation | Class A/B candidate | Separate report-only evidence from explicitly authorized Builder work |
| Investigation method | Methodology | Class A candidate | Reproduction and root-cause evidence; diagnosis never implies fix |
| Security method/classifier | Methodology and optional runtime | Class A/B candidate | Independent evidence, secret safety, prompt-injection defenses, no self-authorization |
| Ship/deploy workflows | Authority-conflicting | Ergonomics reference only | JStack release/action authority remains sole gate; no direct reuse |
| Auto-update/hooks/checkpoints | Mutable control surface | Reject or defer by default | No silent enterprise mutation; explicit opt-in, pins, rollback, and audit if ever supported |
| `.gstack`/`~/.gstack` state | Separate mutable state | Adapter input only | No competing JStack task, evidence, policy, or project identity state |
| Telemetry/tunnels/model calls | External egress | Optional provider surface | Explicit consent, redaction, project isolation, receipts, cost limits, and fail-closed policy |
| Generated host outputs | Generated artifacts | Compatibility research | Generate from JStack canonical sources; do not edit or copy as authority |

Repository text, web content, issues, logs, screenshots, generated skills, and
browser content remain data at their trust boundary. They cannot override the
host, the user, the Unified OS specification, JStack policy, or an authorized
repository instruction file.

## Repository reality versus specification assumptions

The specification's architectural intent remains valid. The following current
repository facts must shape the implementation:

1. JStack Full Team currently selects a fixed 11-role roster; the target is a
   dynamically composed multidisciplinary team with deterministic mandatory
   independence.
2. JStack has roles and capabilities but lacks explicit first-class
   `Specialist`, `Department`, `OperatingProfile`, `ScopeStrategy`, `Provider`,
   `EvidenceContract`, and target `TeamPlan` contracts.
3. The 28,353-line canonical MCP server remains a concentration risk; new
   integration logic must be modular.
4. gstack is broader than directional examples in the specification: 56 skill
   templates, ten host targets, browser/extension surfaces, iOS/device QA,
   GBrain/memory, model/eval, and release/deployment behavior.
5. gstack's Codex generator is not JStack-native integration.
6. Upstream direct writes, release actions, checkpoint commits, hooks, and
   update behavior conflict with JStack's sole-authority model when used
   unchanged.
7. The browser provider is plain HTTP/CLI, not MCP, and requires an adapter.
8. Bun and Chromium are optional prerequisites and Bun is absent in the local
   baseline; core JStack must degrade cleanly without them.
9. gstack CEO review offers explicit scope modes but greenfield/iteration
   defaults can favor expansion; JStack needs a bound `ScopeStrategy` with user
   authority and risk-floor semantics.
10. gstack global/project state, telemetry, browser identity, cookies, and
    egress must not leak across JStack projects or operating profiles.
11. JStack already has Prompt Compiler, context/readiness, Loop, Program,
    Audit, Product Interface, evidence, and release controls. Integration must
    extend them, not create parallel systems.
12. Prompt Compiler's verified long-goal reserved-requirement defect is part of
    the current JStack baseline and needs separate bounded remediation.

## Baseline tests

### JStack commands and results

| Check | Result |
| --- | --- |
| `python3 -m compileall -q mcp scripts tests evals` | PASS |
| `python3 scripts/sync_artifacts.py --check` | PASS — artifacts synchronized |
| `python3 scripts/check_contract_compatibility.py` | PASS — alpha.9 public contracts compatible |
| `python3 scripts/check_product_boundaries.py` | PASS — six commands, 59 canonical tools, 52 frozen aliases, standard-library core, no packaged Proof Plane authority |
| `python3 -m evals.runner.cli verify-lock` | PASS — valid ten-file lock |
| `python3 mcp/jstack/smoke_test.py` | PASS |
| `python3 -m unittest discover -s tests` | PASS — 997 tests in 903.834 seconds; five expected skips |

The five local skips are four schema-validation tests in the two classes
guarded by the absent test-only `jsonschema` package and one Windows-specific
Product Interface privacy-boundary test. Structural schema tests and all
applicable macOS/POSIX tests ran. CI installs the pinned validator and runs the
Windows portable lane.

An initial full run was invalid because the inspection clone did not yet have
the annotated Beta.1 tag and used `/private/tmp` as `TMPDIR`. It reported 21
failures and 57 errors, all collapsing to these two prerequisites:

- `git cat-file -t v0.10.0-beta.1` could not resolve the missing local tag;
- Proof Plane rejected the world-writable `/private/tmp` authority ancestor.

After fetching and verifying the exact annotated tag and selecting a private
mode-0700 user-owned temporary root, all 11 focused macOS TCB tests passed and
the complete 997-test suite passed. No source or safeguard was modified to make
the tests pass.

### gstack baseline test inventory

The upstream free lane declares this reproducible sequence on Linux:

```text
bun install --frozen-lockfile
npx playwright install --with-deps chromium
bun run gen:skill-docs --host all
bun run vendor:xterm
bash browse/scripts/build-node-server.sh
xvfb-run -a bun run test:free
```

The free-test workflow is secretless and has a 20-minute timeout. Separate
Windows, dependency-review, OSV, generated-skill, version, PDF, quality, and
paid/periodic evaluation workflows exist. The paid/evaluation lanes require
provider access and must not be used as baseline proof without their exact
credentials, cost authority, model configuration, and evidence.

The gstack suite was not run locally because Bun is unavailable and Stage 0 did
not authorize or require installing its dependency/runtime graph. This is an
explicit environment limitation, not a claim that gstack tests passed or
failed. The immutable upstream commit and exact expected commands are recorded
so Stage 1 and provider proof-of-concept planning can bind their prerequisites.

## Impact assessment

### Architectural decisions

- Preserve JStack as the sole kernel.
- Treat gstack as a pinned source for classified methodology and optional
  providers, never an equal orchestrator.
- Extend existing JStack gates and state rather than duplicating them.
- Add future integration logic in cohesive modules, not the MCP monolith.
- Require explicit disposition and provenance before any upstream material or
  runtime is adopted.

### Team and role impact

None in Stage 0. The fixed current roster and target dynamic composition are
documented; no role, permission, team selector, or physical-agent behavior
changed.

### Schemas and contracts

None changed.

### Security impact

No executable integration or dependency was introduced. Later stages must
threat-model command injection, path/symlink/TOCTOU boundaries, environment and
secret leakage, prompt injection, poisoned browser/repository content, unsafe
downloads, provider escalation, cross-project state, evidence tampering, stale
approval, external egress, and production action without authority.

### Compatibility impact

None. The six commands, 59 canonical tools, 52 aliases, schemas, receipts,
installer, persisted state, generated copies, and release metadata remain
unchanged.

### Provenance and licensing impact

Both source repositories are MIT licensed. Stage 0 copied or adapted no gstack
source, prompts, templates, wording, installer, or runtime. Any later reuse or
adaptation must record the pinned file and commit, classification, local
adaptation, upstream copyright, MIT notice, review status, and synchronization
policy in JStack's provenance records and `THIRD_PARTY_NOTICES.md` as
applicable.

### Performance and cost impact

None at runtime. The only measured cost is baseline verification time. Future
Solo mode must not pay unconditional Bun, browser, network, model, or large
prompt costs for work that does not use those capabilities.

## Known limitations and residual risks

- gstack's suite was inventoried but not executed locally.
- JStack's test-only JSON Schema validator was absent locally; CI owns that
  matrix coverage.
- No Stage 1 per-capability disposition has yet been recorded.
- No browser/provider sandbox, evidence adapter, or dependency-isolation design
  has yet been approved.
- Prompt Compiler's long-goal reserved requirement mismatch remains open.
- Both upstream repositories can advance after these pins; this baseline must
  not silently follow them.
- No superiority, productivity, security, production-readiness, or enterprise
  claim follows from this repository inspection.

## Stage 0 advance gate

| Requirement | Evidence | Status |
| --- | --- | --- |
| Exact commits recorded | Remote heads, commits, trees, versions, dates, file/byte counts, and license hashes above | PASS |
| Baseline tests known | JStack commands/results and gstack reproducible CI commands above | PASS |
| Current architecture mapped | JStack and gstack architecture, state, runtime, side-effect, host, and trust maps above | PASS |
| Unexplained baseline failures resolved or documented | Corrected JStack full suite passes; gstack non-execution has an explicit prerequisite boundary | PASS |

**Advance-gate decision:** Stage 0 is complete. Stage 1 may create the dual
repository capability matrix and repository map. This decision does not
authorize implementation from later stages, dependency installation, Git
operations, release, deployment, production mutation, or other external
actions outside the user's existing authority.
