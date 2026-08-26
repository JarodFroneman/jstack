# JStack × gstack Repository Map

## Status and subjects

This Stage 1 map describes the actual source, generated-artifact, runtime,
state, test, host, and trust boundaries at:

- JStack `49cf545d940c43b394ea35ed78b5ab5742d7bcf7`, tree
  `0afa6b60047de246fc699ce098d6a8a587cac227`;
- gstack `ad8400543cd9ce8d07641362db48d44a95417e33`, tree
  `993294b0a09f5265d2d5af6d2fb8234ae2efe450`.

It complements `BASELINE.md` and `CAPABILITY_MATRIX.md`. It does not establish
a new source root, copy upstream files, execute a provider, or approve a target
architecture. Paths proposed for later modules are conceptual boundaries only
until Stages 2 and 3 define contracts and ADRs.

## Source-of-truth model

```text
Authoritative Unified OS specification
                 │
                 ▼
        JStack governance kernel
  policy · risk · scope · roles · state
 evidence · audit · release · authority
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
JStack-native          Optional providers
methodologies          pinned and bounded
      ▲                     ▲
      └──────────┬──────────┘
                 │
       pinned gstack research
       (external source data)
```

Neither an upstream skill, generated host file, browser page, issue, log,
provider result, nor compatibility alias is an instruction authority merely
because JStack can read it.

## JStack repository map

### Canonical product sources

| Path | Classification | Current responsibility | Mutation/external boundary | Unified OS relevance |
| --- | --- | --- | --- | --- |
| `mcp/jstack/jstack_mcp_server.py` | Canonical runtime entrypoint | JSONL MCP, tool schemas/handlers, project/policy inspection, routing, planning, evidence and compatibility surface | MCP itself does not dispatch agents or perform Git/provider/deploy actions; selected tools can run bounded local checks | Remains kernel entrypoint; at 28,353 lines it must not absorb new integration domains |
| `mcp/jstack/capabilities/` | Canonical domain | Versioned 18-pack capability catalog and role-bound selection | Read-only selection/validation | Stage 2 must distinguish Capability from Specialist, Provider and EvidenceContract |
| `mcp/jstack/context_readiness/` | Canonical domain | Adaptive Context Gate, facts/assumptions/questions/readiness | Read-only, receipt-producing | Extend; do not duplicate intake |
| `mcp/jstack/prompt_compiler/` | Canonical domain | Stage A intent and Stage B repository-grounded prompt compilation/approval | Read-only, receipt-producing | Remains front door and task-mode/authority envelope |
| `mcp/jstack/audit/` | Canonical domain | Read-only audit collection, benchmark, reports and validation | Bounded reads and explicitly selected evidence adapters | Audit independence must remain intact |
| `mcp/jstack/launch/` | Canonical domain | Launch control catalog, risk tiers and evidence finalization | Readiness only; no deployment authority | Provider observations can satisfy typed controls but not authorize action |
| `mcp/jstack/loop/` | Canonical state domain | Durable bounded goal loop, leases, events, snapshots, criteria and final receipts | Private `~/.jstack` state; child execution stays host-owned | Remains one task-state engine for looping work |
| `mcp/jstack/program/` | Canonical state domain | Phase DAGs, intervention gates, child proofs, revision/invalidation/finalization | Private `~/.jstack` state; external gates non-authorizing | Remains persistent orchestration above delivery modes |
| `mcp/jstack/ui/` | Canonical Product Interface domain | UI applicability, design contract, reference evidence, motion spec/finalization and private reports | Bounded project reads and private evidence/signing state | Design and browser capabilities integrate here without a second UI authority |
| `mcp/jstack/schemas/` | Canonical contracts | Closed JSON schemas for product/evidence/state exchanges | Validation only | Stage 2 schemas belong here if ADR confirms JSON contract approach |
| `mcp/jstack/templates/` | Canonical templates | Enterprise/project policy templates and installed configuration assets | Installer-managed | Profiles/policies must evolve additively |
| `prompts/` | Canonical command prompts | Six operating-mode command entrypoints | Host compliance surface | Operating modes stay distinct from specialists |
| `skills/` | Canonical Codex skills | Dev, Audit, Loop, Evidence Builder and Product UI workflow instructions | Host compliance surface | Later methodology capabilities route through existing workflows |
| `mastery/` | Canonical curricula | Engineering, Audit and Loop mastery | Local profile/evidence state | Must not become implicit authority or persona routing |
| `THIRD_PARTY_NOTICES.md` | Canonical provenance notice | Existing pinned MIT/custom-license research/adaptation records | Documentation | Stage 4 owns gstack-specific immutable provenance |

### Canonical orchestration facts

- `AGENT_ROSTER` currently defines 11 canonical roles.
- `choose_agent_team` treats explicit Full Team as all 11 roles rather than a
  dynamic organization.
- `TEAM_MODES`, `TEAM_DISPATCH_POLICY`, and
  `TEAM_COORDINATION_PROTOCOL` already encode bounded physical agents,
  read/write ownership, evidence, stop conditions, and Lead accountability.
- `jstack_plan`, team planning, specialist-result, and specialist-handoff
  receipts already bind role/capability selection.
- No current first-class schema defines Department, Specialist,
  OperatingProfile, ScopeStrategy, Provider, EvidenceContract, or target
  TeamPlan.

### Existing upstream-gstack compatibility bridge

JStack already contains a narrow read-only discovery bridge in
`mcp/jstack/jstack_mcp_server.py`:

- `find_gstack_root()` checks `GSTACK_ROOT`, `~/.gstack/repos/gstack`, and
  `~/.codex/skills/gstack`;
- `skill_files()` adds discovered upstream `SKILL.md` files to the installed
  skill inventory;
- project detection reports `gstackRoot`, `gstackBin`, `gstackInstalled`, and
  `upstreamGstackOptional`;
- project config discovery recognizes `.gstack/project.{yaml,yml,json}` and
  root `gstack.{yaml,yml}` alongside JStack config names;
- legacy `gstack_list_skills` and `gstack_read_skill` can return bounded
  descriptions/content from installed upstream skills.

This bridge does not execute upstream skills or binaries and does not make
gstack a runtime dependency. Stage 2/3 must explicitly decide whether to retain
it as a compatibility reader, add source/trust labels, or narrow it. Upstream
skill content and `.gstack` configuration must remain external data unless a
versioned JStack contract deliberately accepts specific fields. Discovery
must never imply provider availability, trust, or authority.

### Generated and distribution surfaces

```text
canonical prompts/skills/MCP/domains/schemas/templates
                         │
                         │ scripts/sync_artifacts.py
                         ▼
        umbrella plugin/ + six dedicated plugins/
                         │
                         │ scripts/install.py / install.ps1
                         ▼
        transactional Codex installation + rollback
```

| Path | Classification | Rule |
| --- | --- | --- |
| `plugin/` | Generated umbrella distribution | Never edit independently; exact source maps and tree mirrors are checked |
| `plugins/j-stack-dev/` | Generated dedicated distribution | Contains Product UI plus standard Dev workflow |
| `plugins/jstack-subagents/` | Generated dedicated distribution | Smart bounded specialist-team mode |
| `plugins/jstack-full-team/` | Generated dedicated distribution | Current fixed full-role mode |
| `plugins/jstack-loop/` | Generated dedicated distribution | Durable wrapper mode |
| `plugins/jstack-audit/` | Generated dedicated distribution | Independent read-only audit mode |
| `plugins/jstack-evidence-builder/` | Generated dedicated distribution | Reference preprocessing, no candidate edit |
| `scripts/sync_artifacts.py` | Generator/verifier | Checks exact inventories, bytes, BOMs, JSON, stale/retired artifacts and versions |
| `scripts/install.py`, `scripts/install.ps1` | Transactional installers | Stage, validate, replace, preserve rollback; protected release metadata |

New canonical integration files must be declared in the generation graph when
they are part of installed payloads. Generated copies may never become a second
source of truth.

### Documentation, evaluation, and development-only surfaces

| Path | Purpose | Product boundary |
| --- | --- | --- |
| `docs/adr/` | 45 architecture decisions through v0.11.0 | ADRs describe accepted current design and the Unified OS decisions |
| `docs/migration-*`, system docs | User/maintainer compatibility history | Update only when behavior actually changes |
| `tests/` | Regression modules for product, security, compatibility, state, CI, and Proof Plane behavior | Exact test totals come from the release candidate run, not this map |
| `evals/`, `tools/proof_plane/` | Development-only empirical Proof Plane | Not installed; cannot inherit product authority |
| `product-ui-evals/` | Product UI representative tasks/rubric | Evaluation fixtures, not runtime policy by themselves |
| `prompt-compiler-evals/` | Prompt Compiler task set | Evaluation fixtures, not stored raw user prompts |
| `.github/workflows/ci.yml`, `.github/workflows/codeql.yml` | Six OS/Python combinations plus full POSIX, portable Windows, and independent Python CodeQL scanning | Full history/tags, immutable action pins, test-only validator, compile/sync/compat/boundary/lock/smoke and scanner gates |

### JStack persisted state

| Location | Owner | Contents | Integration rule |
| --- | --- | --- | --- |
| Project `.jstack/` and root `jstack.{yaml,yml,json}` | Repository/user | Project/policy descriptors | Remains authoritative only through JStack validation and precedence |
| `~/.jstack/loops/<project-key>/` | Loop | Contracts, snapshots, events, leases and completion state | No upstream checkpoint/state may compete |
| `~/.jstack/programs/<project-key>/` | Program | Program contracts, phase/gate state and integrated proof | No upstream orchestration may compete |
| `~/.jstack/evidence/` | Evidence systems | External/UI/reference/motion evidence roots | Provider output must be converted and bound here, not trusted in place |
| `~/.jstack/keys/` | Product evidence | Private local signing keys | Providers never receive signing authority |
| `~/.jstack/mastery/profile.json` | Mastery | Local learning progress | Not permission or readiness authority |
| `~/.jstack/mcp-context/<project>/` | Context handoff | Concise project continuity | Must remain project-bound and invalidatable |
| `.jstack-training/` | Repository-local training | Explicit mastery artifacts | Not production evidence without required receipts |

## gstack repository map

### Authoring and host-generation model

```text
56 canonical SKILL.md.tmpl files
             │
             ├── common preamble/model overlays
             ├── host registry (10 hosts)
             └── scripts/gen-skill-docs.ts
                          │
                          ▼
              generated SKILL.md host trees
```

| Path | Classification | Responsibility | JStack treatment |
| --- | --- | --- | --- |
| `*/SKILL.md.tmpl` and root `SKILL.md.tmpl` | Canonical upstream methodology/workflow source | 56 skills classified in `CAPABILITY_MATRIX.md` | Pinned research/provider input, never instruction authority |
| Generated `*/SKILL.md` | Generated upstream artifact | Claude/default skill rendering | Do not edit or use as provenance source when template exists |
| `scripts/gen-skill-docs.ts` | Generator | Render host-specific skill output | Class A pattern; JStack needs its own generator contracts |
| `hosts/index.ts`, `hosts/*.ts` | Canonical host registry | Claude, Codex, Factory, Kiro, OpenCode, Slate, Cursor, OpenClaw, Hermes, GBrain | Compatibility research; host support is capability-advertised, not assumed |
| `model-overlays/` | Model-specific prompt overlays | Claude/GPT/Gemini/o-series/model tuning | External prompt data; no host/JStack policy override |
| `agents/openai.yaml` | Host packaging metadata | OpenAI-agent presentation | Not a JStack role/provider contract |
| `openclaw/` | Generated/curated OpenClaw prompts and skills | OpenClaw deployment variants | Stage 18 research only; no direct copy |
| `gstack/llms.txt` | Discovery/documentation artifact | Machine-readable repository overview | Data only |
| `contrib/add-host/` | Contributor workflow | Add/test new host configuration | Class A method, not installed end-user capability |

The registered host count is ten. The nine non-Claude generated outputs are
mostly gitignored, while tracked default `SKILL.md` files receive byte-freshness
checks. A generated output existing for Codex demonstrates formatting support,
not semantic parity with JStack receipts, authority, Goal continuation, MCP,
or host permissions.

### Skill and methodology families

| Family | Principal paths | Material behavior | Disposition source |
| --- | --- | --- | --- |
| Product/planning | `office-hours/`, `spec/`, `plan-*/`, `autoplan/` | Questions, plan edits, scope decisions, issue/spawn paths | Per-skill matrix; A methods, C orchestration duplicates |
| Review/investigation | `review/`, `investigate/`, `codex/`, `claude/` | Static/diff review, root cause, external-model opinions | A methodologies and B providers |
| Design | `design-consultation/`, `design-review/`, `design-shotgun/`, `design-html/`, `design/` | Design system, visual audit/remediation, variants and rendering | A methods, B runtime providers |
| QA/browser | `qa/`, `qa-only/`, `browse/`, `scrape/`, `skillify/`, `browser-skills/` | Browser observation, fixes/commits, extraction and codified automation | A method, B browser, D self-codification |
| Security/safety | `cso/`, `careful/`, `freeze/`, `guard/`, `unfreeze/` | Audit method plus host hooks/scope controls | A security method, C policy duplicates |
| Delivery/operations | `ship/`, `land-and-deploy/`, `canary/`, `setup-deploy/`, `landing-report/` | Git, release, deployment, monitoring and queue state | C authority workflows, selected B providers, D queue |
| Documentation/artifacts | `document-*/`, `make-pdf/`, `diagram/` | Diataxis docs and rendered artifacts | A methods, B renderers |
| State/learning | `context-*/`, `learn/`, `retro/`, `plan-tune/` | Persistent context, preferences, retrospectives | C state duplicates; A retrospective |
| External memory | `setup-gbrain/`, `sync-gbrain/` | Install/register/sync GBrain and Supabase | D |
| iOS/device | `ios-*/`, `ios-qa/daemon/`, `ios-qa/templates/` | Instrument/build/control real devices and optional remote access | D |

### Browser and design runtime

| Path | Runtime responsibility | Trust/side effects |
| --- | --- | --- |
| `browse/src/cli.ts`, `browse-client.ts` | Start/find daemon and send commands | Local process and state discovery |
| `browse/src/server.ts` | Bun HTTP server, local and optional tunnel listeners | Network listener; command/auth/output boundary |
| `browse/src/browser-manager.ts` | Playwright/Chromium lifecycle | Browser process, profile, cookies and tabs |
| `browse/src/read-commands.ts`, `write-commands.ts`, `cdp-*` | Curated and CDP browser actions | Page reads/mutations and raw protocol risk |
| `browse/src/config.ts` | Resolve `.gstack` state and global config | Can create `.gstack/` and append `.gstack/` to project `.gitignore` |
| `browse/src/content-security.ts`, `security*.ts`, `sanitize.ts` | Prompt-injection filters/classifier and output sanitation | Defense-in-depth; false-positive/negative risk |
| `browse/src/token-registry.ts`, `skill-token.ts`, `tunnel-denial-log.ts` | Session/scoped tokens and denial evidence | Auth material and remote-ingress logs |
| `browse/src/session-persist.ts`, `session-cookie-store.ts` | Persist tabs/cookies/local storage | Credential-class private state |
| `extension/` | Branded Chromium side panel, inspector and terminal UI | Extension privileges, page content and model/terminal bridge |
| `design/src/` | Variant generation, gallery, session, auth and receipted fetch | Model/provider cost, asset provenance and generated code |
| `design-html/vendor/` | Vendored design implementation patterns | License/provenance and stack compatibility |

The browser is a long-lived local HTTP service, not MCP. JStack must not
represent browser availability until it has probed the exact pinned provider
and declared commands. The first provider proof should exclude remote tunnels,
cookie import, raw CDP, sidebar terminal control, model routing, and autonomous
remediation.

### Standalone CLI and cross-cutting systems

| System | Principal paths | State/network behavior | Matrix disposition |
| --- | --- | --- | --- |
| Installation/update | `setup`, `bin/gstack-relink`, `gstack-team-init`, `gstack-update-check`, `gstack-upgrade/` | Writes global/project host files and hooks; checks/pulls network | C/D |
| Egress evidence | `lib/egress-receipt.ts`, `bin/gstack-egress*` | Writes pre-send hash-chain metadata in `~/.gstack/security/egress.jsonl` | A method |
| Tracker injection guard | `bin/gstack-issue-guard`, `lib/tracker-guard.ts` | Wraps external issue/PR text as data | A method |
| Secret redaction | `bin/gstack-redact*`, `lib/redact-*` | Scans content; optional pre-push hook and audit log | B provider |
| Evidence/fingerprint | `bin/gstack-wtree`, `bin/gstack-evidence` | Local content fingerprint and evidence ledger | C duplicate |
| Verify/hooks | `bin/gstack-verify-gate`, `bin/gstack-settings-hook` | Executes trusted repository command from host hooks | C duplicate |
| Workflow memory | `bin/gstack-decision-*`, `review-*`, `timeline-*`, `learnings-*` | Persistent JSONL/project state | C duplicate |
| Profiles/preferences | `bin/gstack-question-*`, `gstack-developer-profile`, `gstack-taste-update` | Personal behavioral/taste state | C duplicate |
| Telemetry | `bin/gstack-telemetry-*`, `gstack-analytics`, `gstack-community-dashboard`, `supabase/functions/` | Optional off-machine analytics plus local dashboards | D |
| Code intelligence | `bin/gstack-code-intelligence`, `lib/code-intelligence/` | Local or external indexing/search with consent state | B provider |
| GBrain | `bin/gstack-gbrain-*`, `lib/gbrain-*`, `supabase/` | Install, remote/local DB, source indexing and memory sync | D |
| Model evaluation | `bin/gstack-model-benchmark`, `scripts/eval-*`, `scripts/test-paid-shards.ts` | External model calls, tokens, cost and result store | D |
| Release/version | `bin/gstack-version-bump`, `gstack-next-version`, `gstack-pr-title-rewrite.sh` | Repository metadata and Git-host workflow | C duplicate |
| iOS device | `bin/gstack-ios-qa-*`, `ios-qa/daemon/` | USB/Tailscale listeners, device tokens, source/codegen/build/deploy | D |
| Artifact renderers | `make-pdf/`, `lib/diagram-render/` | Reads documents; writes PDF/DOCX/HTML/SVG/PNG | B provider |

### gstack persisted state

| Location | Representative contents | Boundary |
| --- | --- | --- |
| Project `.gstack/` | `browse.json`, daemon/console/network/dialog/audit logs, session state, screenshots and temp files | Project-local but created/managed by upstream; may include cookies/page data |
| Project `.gstack-worktrees/` | Parallel/evaluation worktrees | Git/filesystem mutation boundary |
| `~/.gstack/config.yaml` | Feature, telemetry, checkpoint, model and provider configuration | Competing configuration if imported wholesale |
| `~/.gstack/projects/<slug>/` | Plans, test plans, decisions, learnings, retros, evals and reports | Persistent project identity and cross-session data |
| `~/.gstack/security/` | Egress, denial, attack, redaction and device audit logs; salts/tokens | Sensitive metadata; local forensic evidence, not tamper-proof authority |
| `~/.gstack/models/` | Local security classifier model/cache | Disk and supply-chain dependency |
| `~/.gstack/analytics/` | Local usage/telemetry state | Personal usage data |
| `~/.gstack/code-intelligence.json` | Provider choice and consent | Provider configuration and egress policy |
| `~/.gstack` Git/memory worktrees | Optional artifact/GBrain synchronization | Remote Git/source privacy boundary |
| `~/.gstack-dev/` | Legacy eval/worktree state | Migration/cleanup compatibility risk |
| Host skill roots | `~/.claude/skills/gstack`, `~/.codex/skills/gstack-*`, and other registered host paths | Global executable prompt/skill installation |

No `.gstack` or `~/.gstack` record becomes JStack task, approval, evidence, or
policy state merely by being present. A B-class provider may receive a
namespaced private cache, but JStack owns project identity, consent binding,
candidate binding, invalidation and final receipts.

### Dependency and process map

| Layer | Required/current dependencies | Optional/external dependencies |
| --- | --- | --- |
| JStack product core | Python 3.9+ standard library, Git for Git-bound workflows; Node launcher in distribution | Project QA tools selected explicitly; no vendor SDK/network core |
| gstack core/setup | Bun `>=1.0.0`, shell/Git, generated skills | Node on Windows browser path |
| gstack browser | Playwright 1.62.1, Chromium; Bun/Node process | Xvfb/X11 on Linux, real browser cookies, ngrok/SOCKS/tunnels |
| gstack design/artifacts | TypeScript/Bun and renderer-specific code | Model APIs, image generation, fonts/assets, PDF/diagram system tools |
| gstack security | Local filters/classifier and model cache | External scanners, dashboards and telemetry |
| gstack memory/intelligence | Local CLI/state | GBrain, PGLite, Supabase, Sourcebot, Graphify and remote Git |
| gstack release/device | Git/Git-host/deploy CLIs; Swift/Xcode/CoreDevice for iOS | Production providers, Tailscale, real iPhone |

gstack `package.json` directly depends on `@huggingface/transformers`,
`@ngrok/ngrok`, `cross-spawn`, `diff`, `html-to-docx`, `marked`, `playwright`,
and `socks`. Development dependencies include Anthropic SDKs and xterm. JStack
core must not inherit this graph. A provider package must declare and isolate
only the dependencies its capability actually needs.

### gstack test and CI map

| Surface | Paths/workflows | Evidence boundary |
| --- | --- | --- |
| Free tests | `test/`, `browse/test/`, `design/test/`, `make-pdf/test/`; `scripts/test-free-shards.ts`; `free-tests.yml` | Secretless, sharded, strict-output; requires Bun/deps and browser setup |
| Windows | `windows-free-tests.yml`, `windows-setup-e2e.yml` | Curated portability; not full browser parity |
| Generated skills | `skill-docs.yml` | All ten hosts generate; tracked default outputs byte-checked |
| Supply chain | `dependency-review.yml`, `osv-scanner.yml`, `quality-gate.yml` | Useful upstream evidence, not JStack release evidence for a changed adaptation |
| Version/release | `version-gate.yml`, `pr-title-sync.yml`, `actionlint.yml` | Upstream governance only |
| Paid/evals | `evals.yml`, `evals-periodic.yml`, `scripts/test-paid-shards.ts` | Provider credentials/cost and evaluation configuration required |
| Artifact gates | `make-pdf-gate.yml`, `ci-image.yml` | Specific upstream artifacts/images |

JStack must rerun its own tests against adapted code. Upstream green CI can
support provenance but cannot validate a JStack wrapper, schema, permission,
provider, or generated plugin copy.

## Repository overlap and integration seams

| Concern | Current JStack owner | Relevant gstack source | Allowed seam | Forbidden seam |
| --- | --- | --- | --- | --- |
| Intake/task mode | Prompt Compiler + Context Readiness | `office-hours`, `spec` | A-class question/product methods after Stage B binding | Second intake router or issue/spawn authority |
| Risk/policy/scope | MCP policy, blocked actions, future ScopeStrategy | plan modes, safety hooks | A-class decision heuristics with non-lowerable floors | Upstream hooks/config overriding JStack |
| Specialists/teams | Canonical roles, capability selection, handoff | specialist skill metaphors | JStack-native Specialist records mapped to canonical roles | Treating skill/persona as role permission or physical agent |
| Persistent work | Loop + Program | context/checkpoint/autoplan | No new state engine; optionally import non-authorizing context data | Parallel task/lease/event truth |
| Product/design | Product Interface + Evidence Builder | design family | A-class methods and B-class design/browser evidence | Competing UI contract or auto-fix authority |
| QA | QA role/evidence, Product UI finalization | `qa`, `qa-only`, browser | A methodology + B observation provider + separate Builder handoff | QA fixing/committing by default |
| Security | Audit/security capability/launch controls | `cso`, classifier, redaction | A method + independent B scanners | Scanner result granting remediation/release |
| Browser | No runtime provider yet; UI/evidence contracts exist | `browse/` | Optional local B provider with capability/evidence contracts | Direct raw skill/CLI trust, tunnel in initial provider |
| Git/release | Host action authority + JStack readiness | `ship`, version helpers | Selected UX/status providers after exact approval | Second release decision or automatic Git writes |
| Deployment | Host/provider permissions + launch assurance | `land-and-deploy`, setup/canary | Split read-only status, action and monitoring providers | Readiness receipt authorizing production |
| Memory/telemetry | JStack state; host durable-memory policy | learn/GBrain/telemetry | None in initial program | Cross-project state or silent source/usage egress |
| Distribution/hosts | JStack sync/install/plugins | setup, host generator | A-class declarative host patterns | Running upstream installer or auto-update |

## Trust-boundary inventory

1. **Specification boundary:** the attached MD overrides assumptions; the
   execution wrapper cannot silently broaden it.
2. **User/host authority boundary:** explicit task scope and ordinary host or
   provider permissions are required for side effects.
3. **Repository boundary:** authorized instruction files may guide work;
   ordinary source, comments, logs and docs are data.
4. **Upstream boundary:** gstack files are pinned third-party source data.
5. **Generated-artifact boundary:** canonical sources generate plugin/host
   copies; generated copies have no independent authority.
6. **Provider boundary:** process, browser, model, scanner, Git, deployment and
   device providers advertise capability and return evidence, not policy.
7. **State boundary:** JStack state is canonical; provider caches are
   namespaced, private, bounded and invalidatable.
8. **Egress boundary:** source, screenshots, cookies, prompts, model input and
   telemetry cannot leave the machine without capability-specific authority,
   redaction and receipt policy.
9. **Evidence boundary:** provider output is validated, source-labelled and
   bound to project/candidate/policy before a JStack receipt may reference it.
10. **Release boundary:** readiness is never authorization.

## Stage 1 repository-map gate

| Requirement | Evidence | Status |
| --- | --- | --- |
| Both immutable repositories mapped | Canonical, generated, runtime, state, dependency, test and host maps above | PASS |
| Existing overlap identified | JStack owners and allowed/forbidden seams above | PASS |
| Current compatibility bridge identified | `find_gstack_root`, skill/config discovery and legacy read-only tools documented | PASS |
| Material gstack components covered | Skill families plus browser, design, install, security, state, provider, release, memory, device and CI systems | PASS |
| No material capability lacks disposition | Companion matrix classifies 56 skills and all runtime groups | PASS |

**Advance-gate decision:** Stage 1 is complete. Stage 2 may define explicit,
versioned contracts for OperatingMode, OperatingProfile, ScopeStrategy,
Department, Specialist, CanonicalRole, Capability, Provider,
EvidenceContract, and TeamPlan. This map authorizes no dependency, provider,
runtime execution, Git action, release, deployment, or production mutation.
