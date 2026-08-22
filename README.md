<div align="center">
  <img src="docs/assets/jstack-social-preview.svg" alt="JStack: evidence-driven engineering control plane for AI coding agents" width="100%">

  <h1>JStack</h1>
  <p><strong>Evidence-driven engineering control plane for AI coding agents.</strong></p>
  <p>Bounded autonomy. Verifiable delivery. Human authority.</p>

  <p>
    <a href="https://github.com/JarodFroneman/jstack/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/JarodFroneman/jstack/ci.yml?branch=main&amp;style=flat-square&amp;label=CI" alt="CI status"></a>
    <a href="https://github.com/JarodFroneman/jstack/releases/latest"><img src="https://img.shields.io/github/v/release/JarodFroneman/jstack?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=10b981" alt="Latest release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-0f172a?style=flat-square" alt="MIT License"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.9%2B-0ea5e9?style=flat-square&amp;logo=python&amp;logoColor=white" alt="Python 3.9 or newer"></a>
    <a href="mcp/jstack/README.md"><img src="https://img.shields.io/badge/MCP-JSON--RPC-14b8a6?style=flat-square" alt="Model Context Protocol"></a>
  </p>

  <p>
    <a href="#why-jstack">Why JStack</a> &middot;
    <a href="#operating-modes">Operating modes</a> &middot;
    <a href="#quick-start">Quick start</a> &middot;
    <a href="#architecture">Architecture</a> &middot;
    <a href="#trust-boundary">Trust boundary</a> &middot;
    <a href="#documentation">Documentation</a>
  </p>
</div>

---

JStack is an independent, open-source AI engineering workflow, plugin suite,
MCP control plane, and deliberate-practice system for professional
AI-assisted software delivery. It gives one engineer or a supervised team a
consistent operating model for planning, implementation, review, testing,
security, launch assurance, release readiness, durable goal loops, and
multi-phase programs.

Codex is the fully packaged host today. Claude Code can connect to JStack's
standards-based stdio MCP tool plane as a preview integration; host-native
commands and long-running continuation remain explicitly host-specific rather
than being presented as feature-equivalent.

> [!IMPORTANT]
> JStack does not declare generated code "enterprise-ready." It raises
> confidence through evidence bound to the actual project state, then reports
> what remains uncertain. Human engineers retain approval and release
> authority.

## Why JStack

AI can generate code quickly. Production engineering still depends on scope
control, independent checks, reproducible evidence, and accountable decisions.
JStack makes those controls explicit.

| Common failure mode | JStack control |
| --- | --- |
| A short prompt leaves the model to invent users, constraints, or "done" | Inspect-first Adaptive Context Gate with source attribution, disclosed assumptions, and at most three material questions with recommended defaults |
| A prompt drifts away from the real goal | Versioned goal contracts, non-goals, policy floors, and exact-digest confirmation |
| "Tests passed" exists only as prose | QA and security receipts tied to the exact Git revision, workspace, policy, and command |
| Multiple agents collide or duplicate work | Role permissions, write scopes, coordination packets, and controlled dispatch waves |
| A generic role receives a generic prompt | Versioned capability routing adds task-specific methods, evidence requirements, stop conditions, and audit/loop controls without granting new authority |
| Interface output defaults to generic cards and gradients or overwrites a product's visual language | Automatic Product Interface routing preserves the existing design system, selects an editorial or creative profile, and requires exact-state objective visual evidence |
| Meaningful UI state changes snap, over-animate, or ignore reduced-motion preferences | Product UI Motion Intelligence creates a frequency-aware specification before implementation; Beta.6 binds ordinary and reduced runtime measurements to the exact candidate before UI finalization |
| Screenshots or websites are used as vague inspiration or mistaken for implementation proof | Evidence Builder records private, digest-bound reference analysis and optional isolated prototypes while keeping source references separate from candidate UI evidence |
| A launch checklist is incomplete, under-scoped, or “passed” with prose | Risk floors and detected surface hints select 47 controls; JStack derives results from structured, target-bound assertions |
| A long task loses context or loops forever | Durable state, bounded iteration, leases, circuit breakers, and explicit stop conditions |
| A large project is hardcoded into one giant prompt | Project-defined Program -> Phase dependency graphs with independently verified child goals |
| Release confidence or a broad phase request silently triggers publication | Evidence remains separate from execution; external actions stay within explicit user scope and normal host/provider permissions, with no JStack token or terminal ceremony |

## Operating Modes

Choose the smallest operating mode that fits the work. The command is
authoritative; JStack never silently escalates staffing.

| Command | Operating model | Best fit |
| --- | --- | --- |
| `/j-stack-dev` | One Lead Engineer, no subagents | Focused implementation, debugging, maintenance, and contained releases |
| `/jstack-subagents` | Lead plus normally two or three specialists | Cross-cutting work that benefits from targeted security, test, architecture, or domain review |
| `/jstack-full-team` | Eleven professional roles dispatched in controlled waves | High-risk, broad, or release-critical changes requiring full functional coverage |
| `/jstack-loop` | A bounded durable goal loop composed with one selected delivery mode | Work that needs verified iteration across turns, human approvals, external waits, or multiple phases |
| `/jstack-audit` | Independent read-only inspection | Evidence-bound correctness, security, architecture, maintainability, performance, and release review |
| `/jstack-evidence-builder` | One Lead builds a private source-reference bundle without editing the project | Approved screenshots, Figma exports, or exact URLs that should inform later UI implementation |

`/jstack-loop <goal>` uses single-lead delivery by default. State `use JStack
Subagents` or `use JStack Full Team` in the same request when that staffing is
explicitly intended. Audit remains an independent inspection boundary and does
not edit project code.

### Specialist capabilities inside the five delivery commands

JStack upgrades the five delivery/audit commands without changing their
staffing model. Evidence Builder is a separate, explicitly invoked
pre-implementation workflow, not another delivery mode.
The selected delivery mode still decides who works and who may edit; a
deterministic capability plan then decides which task-specific methods each
selected role must apply. For example, an API change can route contract and
compatibility evidence to the existing Architect, Builder, Reviewer, QA, or
Security roles, while an authentication change can add trust-boundary and
negative-authorization evidence.

Every selected capability inherits the role's existing permissions. It cannot
turn a read-only Reviewer into a writer, add a role, widen a path scope, or
authorize deployment. Multi-agent work returns schema-validated specialist
results and privacy-safe telemetry metadata; a signed handoff is issued only
when every expected role is present, current, capability-matched, and free of
unresolved contradictions. See the
[specialist capability system](docs/specialist-capabilities.md).

### Product Interface design and reference evidence

Beta.2 adds `product-ui-design` as an automatic skill for user-facing
interface work inside the five delivery/audit commands. Backend-only or
non-interface work does not activate it. The separate
`/jstack-evidence-builder` command collects approved visual references without
editing the project and without qualifying them as candidate evidence. The
resolution order is fixed: an explicit user instruction wins, then the
project's existing design system, then the domain profile, with
`editorial-calm` as the fallback. `creative-canvas` is selected for spatial,
visual, timeline, node, media, and other creation work; hybrid products keep a
calm shell around the creative workspace.

The system is an original implementation influenced by the qualities users
often value in products such as Claude and Fable: clear hierarchy, disciplined
spacing, restrained color, typography-led grouping, and focused creative
workspaces. It does not copy their proprietary themes, layouts, assets,
branding, or source code, and it implies no affiliation or endorsement.
Existing product tokens, components, accessibility rules, layouts, and brand
constraints are preserved and extended rather than redesigned without an
explicit request.

### Adaptive context across JStack commands

JStack v0.9.1 introduced repository and durable-context inspection before it
asks the user anything. Clear, specific prompts continue immediately. When an
answer could materially change scope, architecture, acceptance evidence, or
safety, JStack asks at most three questions in a round, explains why each
matters, and provides a recommended default. Repository-answerable questions
are forbidden.

Facts remain tagged as user, repository, policy, external evidence, or
inference; assumptions stay visible in the plan and handoff. Low-risk work may
continue on accepted defaults. High-risk security, financial, legal,
destructive, migration, or production gaps remain blocked until explicit
in-conversation confirmation. This is normal chat—not an approval token,
digest-paste, signer, mailbox, or terminal flow. See the
[v0.9.1 migration guide](docs/migration-0.9.1.md).

## How It Works

```mermaid
flowchart LR
    A[Goal and inspected context] --> Q[Adaptive Context Gate]
    Q --> B[Readiness and policy]
    B --> C[Selected delivery mode]
    C --> K[Role-bound capability plan]
    K --> UI[Product Interface contract when UI applies]
    UI --> D[Structured UI, QA, security, launch, review, and audit evidence]
    K --> D
    D --> E{Acceptance contract met?}
    E -- No --> F[Bounded revision or human gate]
    F --> C
    E -- Yes --> G[Completion receipt]
    G --> H[Explicit user scope]
    H --> I[Host/provider action controls]
```

JStack separates four concerns that ordinary prompts tend to collapse:

1. **Intent**: confirm the goal, context, non-goals, risk, scope, and acceptance
   contract.
2. **Execution**: select a right-sized delivery mode and constrain who may
   change what.
3. **Evidence**: bind tests, security coverage, review, approvals, and outputs
   to the current project state.
4. **Action safety**: keep evidence separate from execution and perform
   repository, Git, provider, deployment, or production actions only within
   explicit user scope and normal host/provider permissions.

## What Is In The v0.10.0-beta.6 Prerelease

`v0.10.0-beta.6` completes the planned Product UI motion lifecycle. Beta.5
still creates the frequency-aware, reduced-motion-aware specification before
implementation. After a clean candidate is built and exercised, the new
`jstack_ui_motion_finalize` gate validates bounded host-produced runtime
measurements for every specified interaction and platform in both ordinary and
reduced modes. It checks exact candidate and artifact binding, timing and
property conformance, immediate feedback, interruption behavior, focus and
semantic state, refresh-rate-aware frame budgets, dropped frames, long tasks,
and layout stability. It writes one deterministic private HTML report and
issues a candidate-bound receipt that can be paired with the motion
specification during ordinary `jstack_ui_finalize`. See
[ADR 0027](docs/adr/0027-product-ui-motion-enforcement.md) and the
[Beta.6 migration guide](docs/migration-0.10.0-beta.6.md).

Beta.6 adds no animation runtime and does not operate a browser or native test
harness. The host supplies canonical measurement artifacts beneath JStack's
private UI evidence root; JStack validates those bytes and declared metrics but
does not certify producer honesty or subjective aesthetic quality. Static UI
work keeps the existing finalization path. Beta.4's Prompt Compiler,
Beta.4.1's mandatory complete-prompt approval boundary, the Evidence Builder,
and UI contract v1/v2 remain compatible.

> **Unvalidated prerelease:** `0.10.0-beta.6` enforces deterministic motion
> evidence contracts; it does not itself prove measured design uplift. Beta.1's
> 18-image, 216-attempt, 432-review Proof Study remains deferred and byte-bound
> to the exact annotated `v0.10.0-beta.1` tag. Neither publication nor Product
> Interface receipts validate that study or establish production readiness.

| Capability | What it provides |
| --- | --- |
| Prompt Compiler | Stage A pre-inspection intent and authority normalization; Stage B repository-grounded, source-traceable task contracts; mandatory complete-prompt preview and exact approval binding before planning; deterministic rendering, size budgets, secret rejection, signed project-bound receipts, four rollout modes, and no stored raw prompt or hidden reasoning |
| Product Interface System | Automatic UI-scoped design guidance with `editorial-calm` and `creative-canvas` profiles, hybrid shell/workspace composition, existing-system precedence, platform adapters, Git-bound contracts, creation-time frequency-aware motion specifications, candidate-bound ordinary/reduced motion audits and private reports, objective screenshot-matrix evidence, and release propagation inside delivery workflows; optional reference preprocessing uses the separate Evidence Builder command |
| Beta.1 Proof Plane | Uninstalled maintainer infrastructure for exact 18-image qualification, reviewed task artifacts, 216 write-once attempts, delayed grading, 432 signed blinded reviews, and independently signed evidence verification; until those external gates run, it proves implementation integrity only and makes no performance, uplift, validation, or production-readiness claim |
| Safe Security Operator Stage 0 | Two inert, deterministic audit-mastery labs for CIA, authorization, hostile-repository instruction handling, no-execution/no-network/no-secret boundaries, private coordinated disclosure, and explicit non-authority; Stage 0 does not scan, exploit, patch, publish, deploy, or access production |
| Repository Reconnaissance Stage 1 | A closed `jstack.audit.repository-map.v1` contract that binds static maps to exact Git HEAD/tree state, requires all eight system surfaces, hash-verified source-line citations, graph and trust-boundary integrity, generated-artifact provenance/drift classification, explicit gaps and limitations, and two deterministic independent passes |
| Correctness And Reliability Stage 2 | Closed report and reproduction contracts for exact-Git-bound logic, state-transition, error-handling, and reliability evidence; strong claims require current source hashes, violated invariants, reciprocal static or exact-QA reproductions, complete regression plans, and two deterministic independent passes |
| Security And Threat-Modelling Stage 3 | A closed static threat-model contract with complete STRIDE classification, exact-Git-bound citations, assets, bounded adversaries, trust boundaries, controls, reciprocal abuse cases and verified reachable attack paths, critical-blocker enforcement, pinned versioned standards mappings, secret-safe narratives, and two deterministic independent passes |
| Maintainability And Architecture Stage 4 | A closed baseline/candidate architecture contract covering module boundaries, dependency direction, contracts and compatibility, change amplification, testability, and migration risk; static audits propose only, while implementation attempts verify one separately authorized committed remediation against the exact Git diff and current passing JStack QA evidence |
| Performance And Resource Efficiency Stage 5 | Closed workload, capture, results, and finding contracts with signed exact-Git/workload/command/environment/sample binding; JStack recomputes percentiles, budgets, improvements, and guardrail regressions, while Audit remains non-executing and implementation evidence must come from a separately authorized committed workflow |
| Supply-Chain, Build And Release Integrity Stage 6 | Closed exact-Git inventory and report contracts across major dependency ecosystems; JStack independently enumerates tracked inputs, parses GitHub Actions pins and permissions, verifies source-to-artifact graphs, provenance, generated-copy drift, complete signed dependency-scanner evidence (including optional offline OSV coverage), all discovered QA commands, and one separately committed hardening diff |
| Dynamic And Adversarial Verification Stage 7 | Closed exact-revision campaign/capture contracts with deterministic two-run outcomes, eight explicit adversarial categories, signed command/environment/case bindings, reciprocal hypothesis and false-positive analysis, current QA/security evidence, and strict baseline/candidate harness comparison while Audit remains read-only |
| Enterprise Audit Lead Stage 8 | Exact reconciliation of a current signed Git-bound release audit, finalized finding/result contract, deterministic SARIF 2.1.0, priority-first risk ownership, explicit accepted-risk governance, derived go/no-go, canonical engineering/executive reporting, and a strict prior-validated-baseline-to-current committed remediation comparison while Audit remains read-only |
| Adaptive context | Inspect-first source attribution, disclosed and plan-visible assumptions, a three-question maximum with recommended defaults, non-lowerable high-risk behavior, digest-verified briefs, exact audit-selector binding, and stale-state-bound planning receipts across the command workflows |
| Delivery control | Planning, preflight, health, policy, team dispatch, deterministic review, and release-readiness tools |
| Host-native action safety | No JStack approval challenge, token, signer, mailbox, or terminal command; explicit user scope plus ordinary Codex/provider permissions govern external operations |
| Evidence plane | Session-signed QA and security receipts, complete coverage checks, Git-state binding, and residual-risk reporting |
| Reference Evidence Builder | Private screenshot/Figma/approved-URL bundles, rights and provider disclosures, optional isolated HTML prototypes, and digest-only binding into a later UI contract without candidate-evidence authority |
| Launch assurance | 22 explicit surfaces, four non-lowerable risk tiers, a versioned 47-control catalog, static hint reconciliation, composite structured evidence, independent high-risk scanning, and fail-closed production receipts |
| Specialist capabilities | Pinned, versioned routing for 18 engineering, launch, testing, security, reliability, and handoff capability packs inside the five delivery commands; Evidence Builder remains a separate single-Lead preprocessing workflow |
| Specialist handoff | Machine-validated result and telemetry schemas, per-role signed receipts, contradiction checks, and one current team-handoff receipt |
| Audit system | Read-only quick, standard, deep, and release profiles with deterministic finalization and SARIF output |
| Goal loops | Versioned contracts, private atomic state, one write lease per checkout, circuit breakers, checkpoints, revision, and terminal receipts |
| Program orchestration | Phase-count-agnostic dependency graphs, child-goal proofs, human and external gates, pause-aware budgets, invalidation, recovery, and final integrated evidence |
| Team coordination | Single-lead, specialist-team, and full-team modes with validated roles, permissions, scopes, and controlled waves |
| Mastery system | Separate ten-stage engineering, audit, and loop-engineering curricula with artifacts, assistance caps, repeated attempts, and blind capstones |
| Distribution | Six dedicated command plugins, one optional umbrella plugin, a standalone MCP server, one transactional release-checkout installer, and cross-platform CI |

The MCP exposes 59 canonical `jstack_*` tools, including the canonical-only
`jstack_prompt_compile` two-stage lifecycle, the
`jstack_ui_reference_contract` / `jstack_ui_reference_finalize` reference
lifecycle, the `jstack_ui_contract` / `jstack_ui_finalize` candidate lifecycle,
the `jstack_ui_motion_spec` / `jstack_ui_motion_finalize` motion lifecycle, the shared
`jstack_context_readiness` gate, 13 generic
`jstack_program_*` tools and the three-step `jstack_launch_*` evidence
protocol, plus `jstack_performance_capture`, `jstack_adversarial_capture`, and the delivery, audit, loop, continuity,
specialist-review, and mastery families. The frozen 52 legacy `gstack_*`
aliases remain available for compatibility; the Prompt Compiler and all six
UI tools deliberately have no legacy aliases.

All six workflows compile intent before inspection, display Stage B's complete
rendered prompt, and wait for explicit approval. Only the approved Stage B
response's nested `readinessReceipt` and exact `normalizedBrief` are used as
`context_readiness_receipt` and `context_brief`. Planning verifies the pair so
sourced facts, disclosed assumptions, task mode, authority, and exact Audit
selectors cannot be silently changed after intake.

### Development-only Proof Plane

The [Beta.1 Proof Plane](evals/README.md) surrounds the installed product
without expanding it. Its descriptors and installable-product assets remain
byte-frozen against the exact annotated `v0.10.0-beta.1` tag and its 52-tool
server; CI exports and probes that immutable tag instead of substituting the
live Beta.2 server. Expected runs are manifest-bound so omitted failures cannot
vanish from the denominator. The image qualifications, 216 executions, 432
independent human reviews, scoring, and independent verification have not run,
so the study remains unvalidated and cannot be used as a Beta.2 quality,
superiority, uplift, or production claim.

## Host Compatibility

JStack separates its portable MCP control plane from host-specific command and
continuation surfaces.

| Host | Status | Available today |
| --- | --- | --- |
| Codex Desktop and Codex CLI | Full | Five command plugins, skills, prompts, MCP tools, subagent workflows, and native Goal composition |
| Claude Code | MCP preview | Manual local stdio MCP connection to the complete `jstack_*` tool inventory; Claude-native command packaging and continuation parity are not yet shipped |
| Other MCP-capable coding agents | Protocol-level | The JSONL stdio server may be connected manually, but unlisted hosts are not release-tested or claimed as supported |

The control plane is model-agnostic where the MCP protocol permits it. The
quality claim is deliberately narrower: a host is fully supported only when
its install, commands, permissions, continuation semantics, and evidence flow
are covered by JStack's release tests.

## Quick Start

### Requirements

- Codex Desktop or Codex CLI for the fully packaged workflow
- Claude Code for the optional MCP preview
- Git for commit-bound evidence and release controls
- Python 3.9 or newer
- Node.js 22 for the umbrella `plugin/` layout only; the dedicated Layout B
  plugins remain Python-only
- macOS, Linux, or Windows

Windows supports installation, automatic Product Interface routing, and
session-local contract planning. Beta.2 UI evidence finalization intentionally
fails closed on Windows because the stdlib-only server cannot verify inherited
DACL and reparse privacy for evidence files; begin and finish a release-bound
UI lifecycle on a supported POSIX host with no granting extended ACLs on the
key or evidence roots. Beta.3 Evidence Builder contracts can be planned on
Windows, but reference finalization shares the same POSIX-only privacy boundary.
See [installation](docs/installation.md#product-interface-activation-and-evidence).

### 1. Clone

```bash
git clone https://github.com/JarodFroneman/jstack.git
cd jstack
```

### 2. Validate

```bash
python3 scripts/sync_artifacts.py --check
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

On Windows, replace `python3` with `python` where required. The complete
`unittest discover` suite includes the Apple/POSIX Proof Plane authority and
runs on macOS and Linux. Windows CI instead runs every portable product test,
the portable Proof Plane contract tests in `tests/test_evals.py`, the corpus
lock check, and the MCP smoke test; see [the CI workflow](.github/workflows/ci.yml)
for the exact deterministic module selection.

### 3. Install In Codex

For the simplest transactional installation:

```bash
python3 scripts/install.py
```

The installed skill already routes applicable UI work automatically. To also
reinforce that policy in global instructions, use
`python3 scripts/install.py --manage-agents`. The managed block is bounded and
transactional; the default install leaves `AGENTS.md` byte-for-byte unchanged.
Dedicated plugin Layout B already exposes one copy of the skill through
`j-stack-dev`, so do not install a second direct copy.

PowerShell:

```powershell
.\scripts\install.ps1
```

On Windows, the direct installer uses no-profile PowerShell ACL checks before
mutation, rejects a `CODEX_HOME` ancestry whose owner or allow rules are not
verifiably limited to the current user plus Windows system administrators, and
copies an existing control file's security descriptor onto its staged
replacement. `CODEX_HOME` must remain below the current user's private profile;
ambiguous custom roots fail closed. The wrapper accepts `-CodexHome <path>` and
`-ManageAgents` and propagates Python failures.

The installer stages the complete payload, updates the Codex MCP
configuration, and restores prior targets without overwriting concurrent edits
if a later installation phase fails. Successful upgrades retain one bounded,
private recovery set at
`CODEX_HOME/jstack-backups/install-preimages-latest/`; failure and conflict
recovery sets are preserved separately. Recovery data is never auto-deleted;
verify and explicitly archive or remove `install-preimages-latest` before the
next upgrade. Layout A fails closed without changing `config.toml` when it
contains TOML multiline strings; use the manual Layout B MCP configuration
documented in the installation guide for that case.

### 4. Restart And Verify

Restart Codex or open a new task, then confirm that the JStack commands and
`jstack_*` MCP tools are available. Run the installed MCP smoke test when
validating a managed environment.

For the clean six-plugin command layout, custom `CODEX_HOME` locations,
Claude Code MCP preview, upgrades, rollback, and duplicate-command prevention, read the
[installation guide](docs/installation.md).

## Architecture

```mermaid
flowchart TB
    U[AI coding-agent operator] --> H[Host command or MCP integration]
    H --> M[JStack MCP control plane]

    M --> P[Policy and project binding]
    M --> D[Delivery, capability routing, and team coordination]
    M --> UIC[Product Interface contracts and objective visual evidence]
    M --> E[QA, security, audit, and release evidence]
    M --> L[Bounded goal loops]
    M --> R[Program and phase orchestration]
    M --> T[Mastery and continuity]

    P --> G[(Git project state)]
    D --> G
    E --> G
    UIC --> G
    UIC --> X
    L --> X[(Private ~/.jstack state)]
    R --> X
```

The canonical MCP implementation lives in
[`mcp/jstack/jstack_mcp_server.py`](mcp/jstack/jstack_mcp_server.py). Generated
plugin copies are checked for drift, BOMs, version mismatch, and missing
artifacts before release.

### Control Layers

- **Project binding** distinguishes Git-backed and artifact-only workspaces.
- **Adaptive context** distinguishes sourced facts, assumptions, material gaps,
  and safe defaults before planning or audit execution.
- **Policy** defines non-overridable floors, trusted commands, protected paths,
  and release requirements.
- **Delivery** owns plans, staffing, permissions, scopes, and implementation.
- **Capabilities** add role-bound methods, required evidence, stop conditions,
  and audit/loop controls without expanding those permissions or scopes.
- **Product Interface** detects UI scope, resolves design-system precedence,
  and binds implementation/finalization evidence without authorizing changes.
- **Evidence** owns current QA, security, audit, output, and approval proofs.
- **Loop** owns one bounded Phase -> Iteration convergence contract.
- **Program** owns a project-defined Program -> Phase dependency graph above
  bounded child loops.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the complete component and trust
model.

## Evidence And Release Model

JStack's release path fails closed when required evidence is absent, stale,
incomplete, or bound to a different project state. Depending on policy, the
release gate can require:

- a distinct pre-release base and clean committed candidate;
- complete committed, staged, unstaged, and untracked change evidence;
- current QA, security, deterministic review, and audit receipts;
- a current Product Interface finalization receipt when the actual release
  range changes an applicable user-facing interface;
- current specialist result and handoff receipts when multi-agent capability
  routing is used;
- complete current-tree and release-range secret scanning;
- explicit release approval, rollback, monitoring, and smoke-test references;
- revalidation after any material change or downstream invalidation.

Completion means the acceptance contract passed. It does not execute an
external action or widen task scope.

Release readiness is evidence only: its result always includes
`executionAuthorized=false`. Read
[Host-Native Action Safety](docs/action-safety.md).

## Trust Boundary

> [!WARNING]
> JStack is an engineering control plane, not an operating-system sandbox or a
> compliance certification product.

- The QA runner closes stdin, avoids a shell, scrubs inherited variables,
  isolates `HOME`, caps output and time, and kills its process group. Project
  code still runs with the current user's filesystem and network privileges.
- Session-local receipts reduce accidental and caller-side evidence tampering;
  they do not protect against compromise of the same operating-system account.
- Specialist telemetry stores bounded identifiers, timing, status, counts, tool
  names/statuses, evidence references, and derived digests—not prompts,
  messages, tool arguments, model output, or secret values.
- Loop and program state under `~/.jstack/` is private local state, not a
  distributed lock or multi-tenant security boundary.
- Program human gates are caller-supplied conversational decision records.
  They are not enterprise identity, legal non-repudiation, or organizational
  approval.
- JStack has no custom action-approval token or terminal flow. Stronger
  separation of duties belongs in host and provider controls.
- Audit receipts prove the collected scope, validated structure, and result
  calculation. They do not make every model-authored semantic finding true.
- Product Interface screenshots prove the validated PNG bytes, dimensions,
  matrix coverage, and declared checks. They do not independently prove capture
  honesty, runtime provenance, visual excellence, or user preference; human
  aesthetic approval is optional and is never inferred.
- Audit mastery Stage 0 uses only inert local scenarios and writes only declared
  training artifacts under `.jstack-training/`; passing it grants no execution,
  remediation, publication, release, deployment, or production authority.
- Audit mastery Stage 1 reads only the current committed source snapshot and
  writes only its three declared training artifacts under `.jstack-training/`.
  Its pass proves structural and citation-contract compliance—not semantic
  completeness, vulnerability absence, scanning, remediation, or production
  authority.
- Audit mastery Stage 2 writes only its report, invariant narrative, and
  reproduction manifest under `.jstack-training/`. Static counterexamples run
  nothing; executed cases require an exact-revision passing JStack QA receipt.
  JStack QA is environment-hardened but is not an OS or network sandbox, and a
  Stage 2 pass grants no patch, release, deployment, or production authority.
- Audit mastery Stage 3 writes only its threat-model narrative, closed security
  report, and abuse-case narrative under `.jstack-training/`. It performs no
  repository execution, live exploitation, network or secret access, exploit-
  payload retention, remediation, publication, or production action. A Stage 3
  pass proves evidence-contract integrity—not vulnerability absence,
  exploitability, zero-day detection, standards compliance, or production
  security.
- Audit mastery Stage 4 reads immutable baseline/candidate Git objects and may
  write only its three declared architecture training artifacts. Audit proposes
  rather than edits; implementation evidence must already be committed and
  match current QA. A pass does not prove an optimal architecture or grant
  remediation or production authority.
- Audit mastery Stage 5 may write only its three declared performance training
  artifacts. Audit never executes a benchmark or optimizes code. Captures come
  from a separately authorized discovered command and are signed against the
  exact Git tree, workload, command, local environment, and normalized samples.
  JStack recomputes statistics and guardrail regressions, but local capture is
  not an OS or network sandbox and does not prove workload realism, measurement
  accuracy, production capacity, or production authority.
- Audit mastery Stage 6 may write only its dependency inventory, build trace,
  and supply-chain report under `.jstack-training/`. The evaluator reads
  immutable Git objects, recomputes tracked-input and CI-control evidence, and
  requires a current complete receipt for a passed curated dependency analyzer
  plus every discovered QA command. It performs no package resolution,
  registry access, hardening, or release action, and a pass does not prove
  complete transitive dependencies, reproducible builds, artifact
  authenticity, vulnerability absence, or production authority.
- Audit mastery Stage 7 may write only its adversarial plan, closed
  verification-results envelope, and false-positive analysis under
  `.jstack-training/`. Audit never runs the target or implements a harness;
  captures come from a separately authorized discovered test command and bind
  the exact Git tree, campaign, command, local environment, deterministic
  two-run case set, and digested outcomes. Current QA and security receipts are
  mandatory. Local capture is not an OS or network sandbox, an observed lack
  of external effects is not enforced isolation, and a pass does not prove
  vulnerability absence, exploitability, zero-day detection, release
  readiness, production safety, or production authority.
- Audit mastery Stage 8 may write only its release audit report, finalized
  audit result, deterministic SARIF, and risk register under
  `.jstack-training/`. The evaluator reconciles them with a fresh complete
  release-profile receipt and permits no other dirty path. Every finding must
  have one priority-first owner/disposition record; accepted risk requires the
  exact owner, reason, approval, future expiry, compensating control, and
  residual risk. The controls drill verifies a separately committed candidate
  against a prior passed, Git-immutable Stage 8 baseline and rejects missing
  remediation or detected regression. Audit cannot accept risk, edit code,
  change Git, release, deploy, or access production, and a pass does not prove
  vulnerability absence, zero-day detection, release authorization, or
  production safety.
- Artifact-only projects can use planning and direct operator evidence, but
  cannot receive commit-bound JStack release receipts.

Use a container, VM, or hardened execution host for untrusted repositories.
Read [SECURITY.md](SECURITY.md) before adopting JStack in a production delivery
environment.

## Repository Map

| Path | Purpose |
| --- | --- |
| [`mcp/jstack/`](mcp/jstack/) | Canonical JSON-RPC server, Product Interface catalog and evidence controls, capability registry, delivery controls, audit, loop, program, schemas, curricula, and templates |
| [`skills/`](skills/) | Canonical single-lead, Product Interface, Evidence Builder, audit, and loop skills |
| [`prompts/`](prompts/) | Canonical slash-command prompts |
| [`plugins/`](plugins/) | Six dedicated command plugins |
| [`plugin/`](plugin/) | Optional all-in-one plugin with portable launcher |
| [`mastery/`](mastery/) | Engineering, audit, and loop curricula |
| [`evals/`](evals/) | Development-only Proof Plane contracts, manifest, lock, mock runner, and deterministic scorer; never installed into JStack core |
| [`tests/`](tests/) | Unit, transport, adversarial, release, mastery, installation, and orchestration tests |
| [`docs/`](docs/) | Operating models, protocols, migration guides, and architecture decisions |
| [`jstack.enterprise.json`](jstack.enterprise.json) | This repository's executable JStack policy |

## Development And Verification

```bash
python3 scripts/sync_artifacts.py --write
python3 scripts/sync_artifacts.py --check
python3 scripts/check_contract_compatibility.py
python3 scripts/check_product_boundaries.py
python3 -m evals.runner.cli verify-lock
python3 -m compileall -q mcp scripts tests evals
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
```

CI runs the same compilation, generated-artifact, compatibility,
product-boundary, corpus-lock, and MCP-smoke checks on Ubuntu, macOS, and
Windows with Python 3.9 and 3.12. Ubuntu and macOS run the complete unit and
adversarial suite, including the POSIX/macOS Proof Plane authority. Windows
runs the portable product suite plus portable Proof Plane contract/integrity
coverage; Apple-container execution and POSIX ownership, mode, link, socket,
and SSH authority tests are not claimed as Windows-compatible.

## Documentation

| Start here | Deep dive |
| --- | --- |
| [Installation and host compatibility](docs/installation.md) | [Architecture](ARCHITECTURE.md) |
| [v0.10.0-beta.6 migration guide](docs/migration-0.10.0-beta.6.md) | [Product UI Motion Enforcement](docs/adr/0027-product-ui-motion-enforcement.md) |
| [v0.10.0-beta.5 migration guide](docs/migration-0.10.0-beta.5.md) | [Product UI Motion Intelligence](docs/adr/0026-product-ui-motion-intelligence.md) |
| [v0.10.0-beta.4.1 migration guide](docs/migration-0.10.0-beta.4.1.md) | [Prompt Compiler approval amendment](docs/adr/0025-prompt-compiler.md) · [Prompt Compiler guide](docs/prompt-compiler.md) |
| [v0.10.0-beta.4 migration guide](docs/migration-0.10.0-beta.4.md) | [Prompt Compiler decision](docs/adr/0025-prompt-compiler.md) · [Prompt Compiler guide](docs/prompt-compiler.md) |
| [v0.10.0-beta.3 migration guide](docs/migration-0.10.0-beta.3.md) | [Evidence Builder decision](docs/adr/0024-ui-reference-evidence-builder.md) |
| [v0.10.0-beta.2 migration guide](docs/migration-0.10.0-beta.2.md) | [Product Interface System decision](docs/adr/0023-product-interface-system.md) |
| [v0.10.0-beta.1 prerelease migration guide](docs/migration-0.10.0-beta.1.md) | [Beta.1 Proof Study](docs/adr/0021-beta1-codex-proof-study.md) · [Unvalidated prerelease amendment](docs/adr/0022-beta1-unvalidated-prerelease-distribution.md) |
| [v0.10.0-alpha.10 migration guide](docs/migration-0.10.0-alpha.10.md) | [Proof Foundation decision](docs/adr/0020-proof-foundation.md) |
| [v0.10.0-alpha.9 migration guide](docs/migration-0.10.0-alpha.9.md) | [Enterprise Audit Lead decision](docs/adr/0019-enterprise-audit-lead-stage8.md) |
| [v0.10.0-alpha.8 migration guide](docs/migration-0.10.0-alpha.8.md) | [Dynamic and Adversarial Verification decision](docs/adr/0018-dynamic-adversarial-verification-stage7.md) |
| [v0.10.0-alpha.7 migration guide](docs/migration-0.10.0-alpha.7.md) | [Supply-Chain, Build and Release Integrity decision](docs/adr/0017-supply-chain-build-release-stage6.md) |
| [v0.10.0-alpha.6 migration guide](docs/migration-0.10.0-alpha.6.md) | [Performance and Resource Efficiency decision](docs/adr/0016-performance-resources-stage5.md) |
| [v0.10.0-alpha.5 migration guide](docs/migration-0.10.0-alpha.5.md) | [Maintainability and Architecture decision](docs/adr/0015-maintainability-architecture-stage4.md) |
| [v0.10.0-alpha.4 migration guide](docs/migration-0.10.0-alpha.4.md) | [Security and Threat-Modelling decision](docs/adr/0014-security-threat-model-stage3.md) |
| [Enterprise workflow](docs/enterprise-workflow.md) | [Agent coordination protocol](docs/agent-coordination-protocol.md) |
| [Team operating model](docs/team-operating-model.md) | [Audit system](docs/audit-system.md) |
| [Specialist capability system](docs/specialist-capabilities.md) | [Architecture decisions](docs/adr/) |
| [v0.10.0-alpha.3 migration guide](docs/migration-0.10.0-alpha.3.md) | [Correctness and Reliability decision](docs/adr/0013-correctness-reliability-stage2.md) |
| [v0.10.0-alpha.2 migration guide](docs/migration-0.10.0-alpha.2.md) | [Repository Reconnaissance decision](docs/adr/0012-repository-reconnaissance-stage1.md) |
| [v0.10.0-alpha.1 migration guide](docs/migration-0.10.0-alpha.1.md) | [Safe Security Operator decision](docs/adr/0011-safe-security-operator-stage0.md) |
| [v0.9.1 migration guide](docs/migration-0.9.1.md) | [Adaptive Context Gate decision](docs/adr/0010-adaptive-context-gate.md) |
| [Launch assurance](docs/launch-assurance.md) | [v0.9 migration guide](docs/migration-0.9.md) |
| [Loop system](docs/loop-system.md) | [Program system](docs/program-system.md) |
| [Engineering mastery](docs/mastery-system.md) | [Loop mastery](docs/loop-mastery-system.md) |
| [v0.8.2 migration guide](docs/migration-0.8.2.md) | [Host-native action safety](docs/action-safety.md) |
| [v0.8.1 migration guide](docs/migration-0.8.1.md) | [v0.8 migration guide](docs/migration-0.8.md) |
| [v0.6 migration guide](docs/migration-0.6.md) | [Architecture decisions](docs/adr/) |
| [v0.5 migration guide](docs/migration-0.5.md) | [Third-party notices](THIRD_PARTY_NOTICES.md) |

## Governance

- Report security issues through [SECURITY.md](SECURITY.md).
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.
- Review release history in [CHANGELOG.md](CHANGELOG.md) and
  [GitHub Releases](https://github.com/JarodFroneman/jstack/releases).
- JStack is distributed under the [MIT License](LICENSE).
- Third-party adaptations and pinned source provenance are documented in
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Relationship To gstack

JStack is an independent project. Upstream gstack can provide optional extra
skills, but it is not a runtime dependency and is not required for any JStack
workflow.

---

<div align="center">
  <p><strong>Evidence before confidence.</strong></p>
  <p>Created and maintained by <a href="https://github.com/JarodFroneman">Jay Froneman</a>.</p>
</div>
