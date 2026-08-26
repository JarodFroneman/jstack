# JStack × gstack Capability Matrix

## Status and scope

This is the Stage 1 disposition record for gstack commit
`ad8400543cd9ce8d07641362db48d44a95417e33`, evaluated against JStack commit
`49cf545d940c43b394ea35ed78b5ab5742d7bcf7` and the Stage 0 baseline in
`BASELINE.md`.

The matrix covers all 56 canonical gstack `SKILL.md.tmpl` sources plus the
material runtimes and cross-cutting systems those skills invoke. The sorted
skill-path inventory SHA-256 is
`9de139bdaa445f5ef3b6885054d1f18344f9d0ad5748437d0255415e4560b787`; the
aggregate of the sorted per-file SHA-256 records is
`d45003e90200c859124f1e0e4fffe0ee13da7e56638d3e707a242a1ddf0007e8`.

This document classifies capabilities. It does not copy upstream wording into
JStack, install or execute gstack, approve a provider, or authorize any side
effect. Every component receives one primary disposition:

- **A — Methodology adaptation:** independently express the useful method as a
  JStack-native, role-bound capability. Do not import a giant prompt or its
  authority assumptions.
- **B — Execution provider:** consider a pinned optional provider behind
  JStack contracts, permissions, evidence, timeout, cost, and unavailable-state
  handling.
- **C — Control-plane duplicate:** do not import the upstream router,
  authority, policy, state, audit, orchestration, or release decision. A small
  non-authorizing UX idea may inform an A-class capability separately.
- **D — Reject/defer:** exclude from the current program because value is
  unproven, risk/dependency cost is disproportionate, or deterministic
  constraint and evidence are not yet credible.

## Effective-operation profiles

The profile code in each component row is a compact, normative record of the
required operational fields. It reflects effective behavior found in the full
skill/runtime, not only frontmatter `allowed-tools`.

| Code | Runtime | Effective permissions | Filesystem | Network | Browser/device | Code write | Git write | Deploy | State | Telemetry/egress |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `P00` | Host skill/router | Read, shell, questions, invoke other skills | Inherits invoked capability | Inherits | Inherits | Inherits | Inherits | Inherits | Inherits | Inherits |
| `P01` | Markdown methodology | Read, grep, questions | Repository read | None by default | No | No | No | No | Conversation only | None |
| `P02` | Methodology + local artifact | Read, shell, write, questions | Repository read; project/global artifact write | Optional research | No | Plans/docs only | No | No | `.gstack` or generated artifact | Local logs may occur |
| `P03` | Repository editor methodology | Read, shell, write/edit, grep/glob | Repository read/write | Project-dependent | No | Yes, including plans/docs/source | No unless explicitly combined | No | Repository and local artifacts | Local decision/review logs possible |
| `P04` | Local executor/scanner | Shell, read, bounded output write | Repository read; evidence/tool output write | Tool-dependent | No | No by provider contract | No | No | Evidence/cache/trend files | Local; external tools may egress |
| `P05` | Browser evidence provider | Shell, read, evidence write | Browser state, cookies, screenshots, logs | Yes, target sites | Chromium | No | No | No | `.gstack` browser/session state | Optional local analytics and receipted egress |
| `P06` | Browser remediation workflow | Browser plus repository edit and shell | Browser evidence and repository read/write | Yes | Chromium | Yes | Yes in upstream workflow | No | QA/design reports and browser state | Local analytics/egress possible |
| `P07` | External-model provider | Shell/CLI, repository read, questions | Prompt/session/evidence read-write | Yes, model provider | No | No by provider contract | No | No | Provider session/cost metadata | Provider egress and cost |
| `P08` | Artifact renderer | Shell, read, write | Input read; PDF/HTML/SVG/PNG/diagram output | Optional assets/models | Local render only | Generated artifact only | No | No | Artifact files/cache | None by default |
| `P09` | Host safety hook | Shell, read, hook/config mutation | Host hook and boundary state | No | No | Blocks/allows only | Blocks/allows only | Blocks/allows only | Session/global hook state | Audit log optional |
| `P10` | Git/release workflow | Shell, read/write/edit, agents | Repository and release metadata read/write | Git host/CI | Optional | Yes | Commit/push/PR | No | Release/evidence/queue state | Receipted Git egress where wired |
| `P11` | Deployment workflow | `P10` plus provider/browser operations | Repository, config, evidence, runtime state | Git, CI, deploy provider, production | Optional Chromium | Yes | Yes | Yes, including merge/revert | Deployment/canary state | Production and provider egress |
| `P12` | Installer/updater | Shell and host configuration mutation | Global/project skill, hook, config, binary writes | Git/download endpoints | No | Installed payload | Pull/update commits or refs | No | Global install/update state | Update checks and receipts possible |
| `P13` | Memory/context system | Shell, read/write/search | Global and project memory/state | Optional Git/Supabase/GBrain | No | Guidance/config only | Optional memory-repo Git | No | Persistent cross-session state | Optional telemetry and receipted sync |
| `P14` | Remote-agent tunnel | Shell, network listener, token minting | Tokens, browser state, audit logs | ngrok/Tailscale/remote clients | Remote Chromium tab | Remote page mutation | No by design | No | Tokens, allowlists, denial logs | Mandatory external egress |
| `P15` | iOS/device runtime | Shell, source edit, build/deploy, HTTP control | Swift source, generated bridge, device evidence | USB/CoreDevice; optional Tailscale | Real iPhone | Yes | Possible | Device build/install | Device tokens, allowlists, audit logs | Optional remote-device egress |
| `P16` | Contributor/generator | Shell, read/write/edit, tests | gstack source and generated host trees | Optional package/test fetch | No | Yes | Possible | No | Generated artifacts | None by default |
| `P17` | Browser-flow codifier | Browser, model synthesis, shell, write/test | Browser skills, fixtures, tests, temp output | Target sites/model optional | Chromium | Generated executable script | Optional commit | No | Learned browser skills | Page/model egress possible |

Risk keys used below: `L` is read-only/local; `M` writes bounded local
artifacts or plans; `H` crosses code, browser, model, credential, Git, or
network trust boundaries; `C` can affect production, remote listeners, devices,
host installation, or autonomous authority.

## Canonical skill dispositions

### Routing, planning, review, and investigation

| Component/source | Purpose | Profile | JStack overlap | Distinct value | Risk | Disposition | Required treatment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `gstack` — `SKILL.md.tmpl` | Route an unspecified gstack request | `P00` | JStack commands, Prompt Compiler, risk and capability routing | Upstream discoverability only | `C` inherited authority | **C** | Do not add a second router; expose approved capabilities through JStack routing. |
| `autoplan` — `autoplan/SKILL.md.tmpl` | Sequence CEO, design, engineering, and DX reviews with auto-decisions | `P00+P03` | JStack planning, specialist routing, readiness and approval | Review ordering and explicit taste-decision surfacing | `H` silent decision/scope drift | **C** | Do not import orchestration; individual review methods are classified A below. |
| `office-hours` — `office-hours/SKILL.md.tmpl` | Product discovery through forcing questions and alternatives | `P02` | Prompt Compiler questions and Product role | Demand reality, narrowest wedge, startup/builder framing | `M` scope expansion/state | **A** | Create bounded Product Discovery capability; accepted expansion remains user-owned. |
| `spec` — `spec/SKILL.md.tmpl` | Turn vague intent into a spec, issue, and optional spawned execution | `P00+P02+P10` | Prompt Compiler, context readiness, Program/Loop, external-action authority | Five-phase issue-oriented interview patterns | `C` issue/Git/spawn escalation | **C** | Keep JStack compiler/orchestrator; consider non-authorizing question patterns only through separate A work. |
| `plan-ceo-review` — `plan-ceo-review/SKILL.md.tmpl` | Product/strategy review with four scope modes | `P03` | Product role and planned `ScopeStrategy` | Explicit expansion/selective/hold/reduction modes | `H` scope inflation | **A** | Adapt as CEO/Founder Reviewer; every scope change requires explicit acceptance. |
| `plan-eng-review` — `plan-eng-review/SKILL.md.tmpl` | Architecture, data-flow, failure-mode, and test-plan review | `P03` | Architect/Reviewer roles, planning, security baseline | Diagram-driven completeness and interactive issue resolution | `M` plan edits | **A** | Adapt as role-bound Engineering Plan Review with source traceability. |
| `plan-design-review` — `plan-design-review/SKILL.md.tmpl` | Pre-build UI/UX plan critique and state coverage | `P03` | Product Interface planning and Product role | Structured plan-stage design passes and “what makes it 10” framing | `M` subjective scoring/plan edits | **A** | Adapt criteria, not numeric authority; bind changes to UI contract and user choices. |
| `plan-devex-review` — `plan-devex-review/SKILL.md.tmpl` | Developer-experience planning and friction analysis | `P03` | No dedicated JStack DX method; partial Product/Docs overlap | Persona/TTHW traces and DX expansion/polish/triage | `M` scope edits | **A** | Add a DX capability under Product/Engineering; bind scope mode and evidence. |
| `devex-review` — `devex-review/SKILL.md.tmpl` | Test actual onboarding and developer flows | `P05` | QA, Product, Docs, future browser provider | Measured TTHW and plan-versus-runtime comparison | `H` browser/network/untrusted docs | **A** | Adapt audit method; execute browser observations only through a B provider. |
| `plan-tune` — `plan-tune/SKILL.md.tmpl` | Persist question preferences and behavioral profile | `P13` | Adaptive Context Gate, Prompt Compiler, mastery profile | Per-question preference feedback | `H` can suppress material questions/profile privacy | **C** | Do not create a competing gate/profile; mandatory risk questions cannot be tuned away. |
| `investigate` — `investigate/SKILL.md.tmpl` | Root-cause debugging before correction | `P03` | Investigator role, diagnosis task mode | Four-phase method and three-failed-fix stop | `H` upstream combines diagnosis and implementation | **A** | Adapt investigation law; diagnosis receipt never grants Builder authority. |
| `review` — `review/SKILL.md.tmpl` | Pre-landing structural code review | `P03` | Reviewer, Audit, security and QA evidence | Focus on latent production bugs and trust boundaries | `H` upstream may auto-edit/use agents | **A** | Adapt read-only methodology; remediation requires a separate authorized task. |
| `codex` — `codex/SKILL.md.tmpl` | Codex review/challenge/consult provider | `P07` | Specialist review and future Provider model | Cross-model independent opinion with continuity | `H` code/model egress and cost | **B** | Optional declared model provider; no pass authority or silent fallback. |
| `claude` — `claude/SKILL.md.tmpl` | Claude review/challenge/consult provider on other hosts | `P07` | Same as Codex provider path | Cross-model independent opinion | `H` code/model egress and cost | **B** | Same provider contract and disclosure requirements; unavailable is explicit. |
| `benchmark-models` — `benchmark-models/SKILL.md.tmpl` | Compare Claude, GPT, and Gemini on cost/latency/quality | `P07` | Stage 19 empirical proof and evaluation planning | Cross-provider comparative measurements | `H` denial-of-wallet and judge bias | **D** | Defer until evaluation schemas, budgets, consent, and non-LLM ground truth exist. |
| `retro` — `retro/SKILL.md.tmpl` | Engineering retrospective and trend analysis | `P02` | Program/Loop history, mastery and observability | Team-aware learning and trend method | `M` contributor profiling/privacy | **A** | Adapt with de-identification, opt-in personal feedback, and evidence limits. |

### Product, design, documentation, and artifacts

| Component/source | Purpose | Profile | JStack overlap | Distinct value | Risk | Disposition | Required treatment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `design-consultation` — `design-consultation/SKILL.md.tmpl` | Create product design direction and `DESIGN.md` | `P03` | Product Interface and UI/UX design intelligence | Coherent greenfield design-system consultation and preview | `H` web research, fonts/assets, repo writes | **A** | Adapt into Design Department planning; existing design system retains precedence. |
| `design-html` — `design-html/SKILL.md.tmpl` | Turn approved direction into HTML/CSS | `P03` | Product UI implementation | Layout/content reflow checks and design-type routing | `H` generated code/vendor assumptions | **A** | Adapt implementation guidance only; use project stack and Product Interface gates. |
| `design-review` — `design-review/SKILL.md.tmpl` | Live visual audit, fix, commit, and reverify | `P06` | Product Interface audit, motion and evidence | Visual slop checklist and before/after evidence loop | `C` auto-remediation and commits | **A** | Adapt audit methodology only; browser is B and fixes require separate Builder authority. |
| `design-shotgun` — `design-shotgun/SKILL.md.tmpl` | Generate and compare multiple visual variants | `P05+P07+P08` | Evidence Builder and Product Interface references | Comparison board, structured selection, taste feedback | `H` model/network cost, asset provenance, taste privacy | **B** | Optional design-exploration provider with originality, provenance, budget, and approval contracts. |
| `document-generate` — `document-generate/SKILL.md.tmpl` | Generate Diataxis documentation | `P03` | Documentation role and handoff | Explicit tutorial/how-to/reference/explanation coverage | `M` repository doc writes | **A** | Adapt as Docs capability; source-grounded and scoped to authorized files. |
| `document-release` — `document-release/SKILL.md.tmpl` | Reconcile docs, diagrams, changelog, and TODOs after a change | `P03` | Documentation role, release plan and compatibility checks | Diff-to-document coverage map and drift checks | `H` may alter VERSION/release docs | **A** | Adapt documentation reconciliation; version/release mutations remain separate. |
| `diagram` — `diagram/SKILL.md.tmpl` | Render Mermaid/Excalidraw/SVG/PNG diagrams | `P08` | No dedicated core renderer; architecture docs use diagrams | Editable plus rendered multi-format output | `M` renderer/parser and artifact writes | **B** | Optional artifact provider; sanitize source and avoid mandatory core dependency. |
| `make-pdf` — `make-pdf/SKILL.md.tmpl` | Render Markdown to PDF/HTML/DOCX | `P08` | Documentation artifacts only | Publication-quality multi-format output | `H` HTML/render parser and asset boundary | **B** | Optional artifact provider; sandbox parsing and record tool/version provenance. |

### QA, browser, performance, and security

| Component/source | Purpose | Profile | JStack overlap | Distinct value | Risk | Disposition | Required treatment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `browse` — `browse/SKILL.md.tmpl` | Persistent low-latency Chromium interaction and evidence | `P05` | Product UI evidence and QA need a runtime provider | Persistent tabs/cookies, broad interaction and screenshots | `H` hostile pages, credentials, network and browser state | **B** | Wrap behind optional Browser Provider; no direct skill installation. |
| `open-gstack-browser` — `open-gstack-browser/SKILL.md.tmpl` | Launch visible branded Chromium and sidebar | `P05` | Future Browser Provider UX | Human-observable actions and handoff | `H` extension/model/cookie attack surface | **B** | Provider UI only after browser core contract; never required for JStack core. |
| `setup-browser-cookies` — `setup-browser-cookies/SKILL.md.tmpl` | Import selected authenticated browser cookies | `P05` | No current JStack cookie provider | Authenticated QA sessions | `C` session theft and cross-project leakage | **B** | Separate explicit credential-class consent, domain allowlist, private storage, expiry and deletion. |
| `scrape` — `scrape/SKILL.md.tmpl` | Read-only web data extraction | `P05` | Evidence Builder captures references but does not generalize scraping | Repeatable structured extraction | `H` injection, terms, privacy, SSRF/egress | **B** | Optional read-only provider; legal/authority, URL and content-as-data controls apply. |
| `skillify` — `skillify/SKILL.md.tmpl` | Convert a scrape prototype into executable browser skill/tests | `P17` | No JStack self-modifying browser-skill model | Fast repeated site automation | `C` generated executable persistence and site drift | **D** | Defer self-codifying runtime; static reviewed adapters can be proposed later. |
| `qa-only` — `qa-only/SKILL.md.tmpl` | Report-only browser QA with repro evidence | `P05` | QA role and Product UI evidence | End-user-flow health report | `H` browser/network and screenshot privacy | **A** | Adapt QA method; observations supplied by approved B browser provider. |
| `qa` — `qa/SKILL.md.tmpl` | Browser test, automatic fixes, commits, and regression tests | `P06` | QA, Builder, review and specialist handoff | Severity-tiered test/fix/reverify method | `C` QA-to-Builder escalation and Git writes | **A** | Adapt QA methodology only; split evidence, remediation request, Builder work and revalidation. |
| `benchmark` — `benchmark/SKILL.md.tmpl` | Browser performance baselines and regression trends | `P04+P05` | Performance capture/audit capability | Live Web Vitals/resource trend capture | `H` target variance and browser/network state | **B** | Browser performance provider; bind workload, environment, candidate and raw evidence. |
| `health` — `health/SKILL.md.tmpl` | Execute project checks and calculate a quality trend | `P04+P02` | QA, audit and preflight | One dashboard over existing tools | `H` repository-controlled command execution; reductive score | **B** | Optional local check provider; preserve individual evidence and do not treat score as authority. |
| `canary` — `canary/SKILL.md.tmpl` | Post-deploy browser monitoring and anomaly evidence | `P05` | Launch controls, monitor and rollback planning | Periodic visual/console/performance comparison | `C` production access and false rollback signal | **B** | Read-only production monitor provider; cannot deploy or roll back. |
| `cso` — `cso/SKILL.md.tmpl` | Infrastructure-first security and threat-model methodology | `P01+P02+P04` | JStack Audit/security capability and launch assurance | Daily/comprehensive modes, LLM/skill supply-chain focus | `H` active scanning, secret handling, confidence thresholds | **A** | Adapt methodology; external scanners are separate B providers and findings are non-authorizing. |

### State, safety, installation, release, and external systems

| Component/source | Purpose | Profile | JStack overlap | Distinct value | Risk | Disposition | Required treatment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `context-save` — `context-save/SKILL.md.tmpl` | Persist Git state, decisions, and remaining work | `P13` | Loop/Program durable state and handoff | Conductor workspace handoff UX | `H` competing/stale task state | **C** | Keep one JStack state engine; import no independent checkpoint authority. |
| `context-restore` — `context-restore/SKILL.md.tmpl` | Restore saved work context | `P13` | Loop/Program recovery and continuity | Branch-aware fallback | `H` stale/cross-project context | **C** | Use JStack recovery and explicit invalidation only. |
| `learn` — `learn/SKILL.md.tmpl` | Search, prune, and export learned project patterns | `P13` | Mastery, context and external durable-memory policy | User-visible learning management | `H` privacy, poisoning and cross-project leakage | **C** | Do not create a competing memory authority; later integrations must be provider-scoped. |
| `careful` — `careful/SKILL.md.tmpl` | Warn/deny destructive commands | `P09` | Host permissions, JStack blocked actions and risk policy | Host-hook command interception | `C` inconsistent host enforcement/override | **C** | Keep JStack and host safety floors; do not advertise hook equivalence across hosts. |
| `freeze` — `freeze/SKILL.md.tmpl` | Restrict edit scope to one directory | `P09` | JStack assigned scope and host sandbox | Interactive edit-boundary UX | `C` false containment if hook bypassed | **C** | Scope remains a JStack/host permission contract, not an upstream hook. |
| `guard` — `guard/SKILL.md.tmpl` | Combine destructive warnings and edit freeze | `P09` | Same as careful/freeze | Convenience only | `C` false safety guarantee | **C** | No second policy mode. |
| `unfreeze` — `unfreeze/SKILL.md.tmpl` | Remove edit restriction | `P09` | JStack authority changes require explicit user action | Convenience only | `C` privilege widening | **C** | Never let a skill widen JStack or host authority. |
| `gstack-upgrade` — `gstack-upgrade/SKILL.md.tmpl` | Update global/vendored gstack installations | `P12` | JStack installer/release and target upstream sync lifecycle | Upstream migration UX | `C` silent supply-chain mutation | **C** | Replace with pinned, reviewed, explicit JStack upstream-sync process. |
| `ship` — `ship/SKILL.md.tmpl` | Test, version, commit, push, and open PR | `P10` | JStack preflight/review/release/action authority | Practical release sequencing and evidence reuse UX | `C` Git/release authority escalation | **C** | Do not import workflow; selected UX ideas may be adapted behind JStack authority. |
| `land-and-deploy` — `land-and-deploy/SKILL.md.tmpl` | Merge, deploy, verify, and revert | `P11` | JStack release decision, external action and launch assurance | End-to-end deployment ergonomics | `C` production mutation | **C** | JStack remains sole decision; provider operations are separate B contracts with explicit approval. |
| `setup-deploy` — `setup-deploy/SKILL.md.tmpl` | Detect and persist deployment-provider configuration | `P03` | Launch project contract and repository instructions | Multi-provider configuration discovery | `H` writes trusted instruction file/production metadata | **B** | Optional provider-discovery adapter; preview changes and never store secrets. |
| `landing-report` — `landing-report/SKILL.md.tmpl` | Read workspace/version ship queue | `P04` | Partial release state and Git-host inspection | Multi-workspace version-slot visibility | `H` Git-host access and weak relevance to core | **D** | Defer until a JStack-native release-queue need and evidence model are proven. |
| `setup-gbrain` — `setup-gbrain/SKILL.md.tmpl` | Install/configure GBrain, PGLite/Supabase, and MCP | `P13` | JStack durable-memory policy is deliberately external | Symbol-aware cross-machine memory | `C` install, secrets, remote DB and competing state | **D** | Out of current scope; do not auto-install or register an MCP. |
| `sync-gbrain` — `sync-gbrain/SKILL.md.tmpl` | Re-index repository into GBrain and update guidance | `P13` | Repository inspection/search and durable-memory boundary | Remote/local semantic code retrieval | `C` source egress and instruction-file mutation | **D** | Defer; code-intelligence provider is classified separately with stricter scope. |
| `pair-agent` — `pair-agent/SKILL.md.tmpl` | Expose a browser tab to a remote agent | `P14` | No required JStack remote-browser authority | Cross-host browser collaboration | `C` tunnel/token/page control | **D** | Reject from initial provider; reconsider only after local Browser Provider proof and threat model. |

### iOS and contributor-only capabilities

| Component/source | Purpose | Profile | JStack overlap | Distinct value | Risk | Disposition | Required treatment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ios-qa` — `ios-qa/SKILL.md.tmpl` | Real-device SwiftUI QA over CoreDevice/HTTP | `P15` | Product Interface has stack-neutral QA contracts, no device runtime | Vision-driven physical-device state control | `C` device bridge, source inspection, tunnels and tokens | **D** | Defer until generic provider model, iOS demand and independent security review exist. |
| `ios-fix` — `ios-fix/SKILL.md.tmpl` | Automatically edit, rebuild, deploy and verify iOS fixes | `P15` | Builder/QA separation | Closed device find/fix/verify loop | `C` autonomous code and device deployment | **D** | Reject automatic authority combination; future remediation must use JStack roles. |
| `ios-design-review` — `ios-design-review/SKILL.md.tmpl` | Apple HIG visual review on a real device | `P15` | Product Interface design review | Physical-device screenshots and state coverage | `C` device/data access and subjective scoring | **D** | Defer runtime; generic HIG guidance may be researched independently later. |
| `ios-clean` — `ios-clean/SKILL.md.tmpl` | Remove DebugBridge instrumentation | `P15` | No current bridge | Cleanup convenience | `C` broad source/package mutation | **D** | Not applicable without an approved iOS provider. |
| `ios-sync` — `ios-sync/SKILL.md.tmpl` | Regenerate bridge templates/accessors | `P15` | Generated-copy lifecycle only in concept | Typed device-state accessor generation | `C` upstream template and source mutation | **D** | Not applicable without an approved iOS provider. |
| `gstack-contrib-add-host` — `contrib/add-host/SKILL.md.tmpl` | Add a declarative coding-host configuration | `P16` | JStack packaging and Stage 18 host compatibility | Central host registry and generated-host discipline | `M` generated drift/host assumptions | **A** | Adapt the declarative compatibility method; do not copy gstack host output as authority. |

## Material runtime and cross-cutting dispositions

These rows prevent a skill-level A classification from accidentally importing
its unsafe execution substrate.

| Component/source | Purpose | Profile | JStack overlap / distinct value | Risk | Disposition | Required treatment |
| --- | --- | --- | --- | --- | --- | --- |
| Skill template generator — `scripts/gen-skill-docs.ts`, `hosts/*.ts` | Render canonical templates for ten host layouts | `P16` | Overlaps JStack generated plugin copies; useful declarative host model | `M` generated drift | **A** | Independently design JStack host adapters and exact-generation checks. |
| Upstream setup/install/uninstall — `setup`, `bin/gstack-relink`, `bin/gstack-team-init`, `bin/gstack-uninstall` | Mutate host skill/config/hook layouts | `P12` | Duplicates JStack transactional installer; no unique control value | `C` host mutation | **D** | Never execute as part of integration. |
| Update system — `bin/gstack-update-check`, `gstack-upgrade/` | Check/pull/migrate upstream | `P12` | Duplicates future pinned synchronization lifecycle | `C` silent supply-chain drift | **C** | Replace with explicit immutable provenance review and rollback. |
| Browser daemon/client — `browse/src/server.ts`, `browse/src/cli.ts`, `browse/src/browser-manager.ts` | Persistent Playwright command runtime over loopback HTTP | `P05` | No JStack runtime equivalent; high-value low-latency provider | `H` browser/network/process boundary | **B** | Candidate Browser Provider core after dedicated proof of concept. |
| Browser command surface — `browse/src/read-commands.ts`, `write-commands.ts`, `commands.ts` | Read and mutate page state | `P05` | Product UI QA/evidence execution | `H` page mutation and hostile output | **B** | Declare command-level capabilities; default deny mutating commands not required by contract. |
| Browser extension/sidebar — `extension/`, `browse/src/terminal-agent*.ts` | Visible browser, sidebar agent and terminal pairing | `P05+P07` | Human-observable UX; otherwise optional | `C` extension, model and terminal attack surface | **B** | Separate optional provider capability; not required for headless local proof. |
| Browser token and listener security — `browse/src/token-registry.ts`, `server.ts`, `tunnel-denial-log.ts` | Loopback auth and scoped tunnel denial | `P05+P14` | Useful provider security patterns | `C` auth/tunnel bypass risk | **B** | Re-review independently; local-only listener is initial floor, tunnel excluded. |
| Remote pair/tunnel runtime — `pair-agent/`, `@ngrok/ngrok`, `browse/src/socks-bridge.ts` | Remote agent access to browser | `P14` | No current requirement | `C` public ingress and token delegation | **D** | Exclude from initial and enterprise provider profiles. |
| Cookie import — `browse/src/cookie-import-browser.ts`, `cookie-picker-*` | Copy selected real-browser sessions | `P05` | Enables authenticated QA | `C` credential/session exposure | **B** | Separate credential-class capability; not part of default browser availability. |
| Browser prompt-injection defenses — `content-security.ts`, `security-classifier*.ts`, `sanitize.ts` | Filter/label hostile content and sanitize outputs | `P04+P05` | Complements JStack untrusted-content policy | `H` classifier false positives/negatives and model cache | **B** | Defense-in-depth provider signal; never sole policy authority or bypass switch. |
| Browser evidence capture — `activity.ts`, `audit.ts`, `snapshot.ts`, `network-capture.ts`, `screenshot-size-guard.ts` | Produce page/runtime observations | `P05` | Needed by Product UI/QA evidence contracts | `H` PII, cookies, oversized/poisoned artifacts | **B** | Convert to closed JStack evidence with redaction, bounds and candidate binding. |
| Egress receipts — `lib/egress-receipt.ts`, `bin/gstack-egress*` | Record attempted off-machine sends in a hash chain | `P04` | JStack has receipts but no unified egress ledger | `M` incomplete sink coverage/truncation limits | **A** | Adapt the pre-send evidence principle into JStack-native metadata-only events. |
| Tracker trust envelope — `bin/gstack-issue-guard`, `lib/tracker-guard.ts` | Label issue/PR text as untrusted data | `P04` | Matches Prompt Compiler source labels and injection controls | `M` normalization bypass risk | **A** | Adapt deterministic ingress envelope and adversarial corpus. |
| Redaction/pre-push guard — `bin/gstack-redact`, `bin/gstack-redact-prepush`, `lib/redact-*` | Detect and block credential leakage | `P04+P09` | Complements JStack security evidence | `H` false negatives and hook authority | **B** | Independent optional scanner; hook installation remains explicit and non-authorizing. |
| Working-tree fingerprint/evidence ledger — `bin/gstack-wtree`, `bin/gstack-evidence` | Bind command evidence to local content | `P04+P13` | Duplicates JStack project/candidate fingerprint and receipts | `H` competing evidence truth | **C** | Do not create a second fingerprint or evidence authority. |
| Verification stop hook — `bin/gstack-verify-gate`, `bin/gstack-settings-hook` | Prevent session end until configured command passes | `P09+P04` | Duplicates Loop/Goal and host control | `C` repository-command execution and hook bypass | **C** | Use JStack acceptance gates; no implicit hooks. |
| Checkpoint/context engine — `context-*`, `bin/gstack-repo-mode`, checkpoint configuration | Persist/resume work and optional WIP commits | `P13+P10` | Duplicates Loop/Program state and Git authority | `C` stale state/automatic commits | **C** | Retain JStack leases, events, snapshots and explicit Git authorization. |
| Learning/decision/review/timeline stores — `bin/gstack-learnings-*`, `decision-*`, `review-*`, `timeline-*` | Persistent local workflow memory | `P13` | Overlaps JStack state/mastery and durable-memory policy | `H` poisoning, privacy and divergence | **C** | One JStack state model; selected retrospective method remains A. |
| Question/taste/developer profiles — `bin/gstack-question-*`, `gstack-taste-update`, `gstack-developer-profile` | Learn preferences and question behavior | `P13` | Overlaps Adaptive Context and Product UI preferences | `H` personal profiling and safety suppression | **C** | No implicit profile authority; future preference data must be opt-in and non-lowering. |
| Configuration system — `bin/gstack-config`, `.gstack` and `~/.gstack` config | Govern upstream features and defaults | `P13` | Duplicates JStack policy/profile state | `H` competing policy and project identity | **C** | JStack owns integrated configuration; provider config is namespaced and bounded. |
| Telemetry/community analytics — `bin/gstack-telemetry-*`, `gstack-analytics`, `supabase/functions/` | Local/remote usage analytics | `P13` | Not required for initial JStack value | `H` privacy and egress | **D** | No upstream telemetry in integrated paths; later JStack telemetry needs separate approval. |
| GBrain/memory synchronization — `bin/gstack-gbrain-*`, `lib/gbrain-*`, `supabase/` | Local/remote semantic memory and code index | `P13` | Separate from JStack governance; Codex durable memory is host-owned | `C` source/secret egress and cross-project state | **D** | Exclude from current program. |
| Code-intelligence multiplexer — `bin/gstack-code-intelligence`, `lib/code-intelligence/` | Select GBrain/Sourcebot/Graphify or grep | `P04+P13` | JStack inspection currently uses native repository tools | `H` repository indexing and external query egress | **B** | Optional provider only for large repos, with per-project consent and local fallback. |
| Design runtime — `design/src/`, `design-html/vendor/` | Generate/compare/render design variants | `P07+P08` | Product Interface and Evidence Builder need optional execution | `H` model, asset, licensing and generated-code risk | **B** | Prove one bounded variant provider before adopting any runtime. |
| PDF/diagram renderers — `make-pdf/`, `lib/diagram-render/` | Produce durable visual documents | `P08` | Optional documentation evidence | `H` parser/render dependency and artifact safety | **B** | Keep optional, sandboxed and version-recorded. |
| Release/version/PR helpers — `bin/gstack-version-bump`, `gstack-next-version`, `gstack-pr-title-rewrite.sh` | Mutate version metadata and Git-host state | `P10` | JStack release metadata and action authority | `C` release mutation | **C** | Reimplement only approved UX under JStack release controls. |
| Deployment detection/status helpers — `setup-deploy/`, provider-specific commands in `land-and-deploy/` | Discover provider and query/perform deployment | `P11` | Launch controls need provider observations/actions | `C` production authority | **B** | Split read-only status from action; every action requires exact user/host authorization. |
| Model/evaluation runners — `scripts/test-paid-shards.ts`, `scripts/eval-*.ts`, `model-overlays/` | Paid model runs, collection and comparison | `P07` | Stage 19 empirical proof needs evaluation, not upstream authority | `H` cost, provider drift and judge bias | **D** | Research only until JStack evaluation contracts and budgets exist. |
| Browser-skill store — `browser-skills/`, `skillify/` | Persist generated site-specific automation | `P17` | No JStack executable-learning model | `C` self-modifying executable data | **D** | Exclude; reviewed static adapters may be introduced through ordinary code review. |
| iOS bridge/daemon — `ios-qa/`, `bin/gstack-ios-qa-*` | Instrument, expose and control real apps/devices | `P15` | No current generic device provider | `C` source, device, tunnel and production-like state | **D** | Defer entire provider family. |
| CI and free-test sharding — `.github/workflows/`, `scripts/test-free-shards.ts`, `test/` | Cross-platform generated-output, dependency, security and free-suite checks | `P16` | JStack already has multi-OS CI; upstream adds Bun/browser patterns | `M` test classification and runner trust | **A** | Adapt useful verification patterns only after relevant provider code exists. |

## Disposition summary

### Skill inventory

| Disposition | Count | Meaning for this program |
| --- | ---: | --- |
| A | 18 | Re-express bounded methodology in original JStack-native contracts |
| B | 13 | Consider only through optional provider contracts |
| C | 14 | Preserve JStack control plane; do not import upstream implementation |
| D | 11 | Exclude or defer from the current implementation program |
| **Total** | **56** | Every canonical `SKILL.md.tmpl` is classified exactly once |

### Integration rule

An A or B disposition is not implementation approval. Before code is added,
the relevant later stage must define canonical role, risk floor, scope
strategy, permissions, provider capability, evidence contract, state and
invalidation, optional dependency behavior, source provenance, security tests,
and measurable acceptance criteria. C and D components may not re-enter under
a renamed command or generated host copy.

## Stage 1 capability-matrix gate

- All 56 canonical skill templates have one primary A/B/C/D disposition.
- Material runtimes and cross-cutting tools have separate dispositions, so an
  A-class methodology cannot smuggle in B/C/D execution behavior.
- Required operational fields are recorded through the effective-operation
  profiles.
- JStack overlap, distinct value, risk, and required treatment are explicit.
- No disposition authorizes source reuse, provider execution, release, or
  deployment.

The capability-matrix portion of the Stage 1 gate is **PASS**, subject to the
companion `REPOSITORY_MAP.md` passing its coverage check.
