# Changelog

## 0.10.0-beta.3 - 2026-08-19 - Evidence Builder prerelease

### Added

- Added `/jstack-evidence-builder` as a sixth, explicitly invoked workflow for
  user-provided screenshots, Figma exports, and approved URL captures.
- Added canonical-only `jstack_ui_reference_contract` and
  `jstack_ui_reference_finalize` tools, taking the live surface to 56 canonical
  `jstack_*` tools while preserving all 52 frozen `gstack_*` aliases.
- Added private, hash-bound reference contracts and bundles with rights,
  redaction, provider-disclosure, image, isolated-prototype, and path-safety
  validation. Reference receipts may be bound into `jstack_ui_contract` but can
  never satisfy candidate UI finalization or another release gate. Ordinary
  UI contracts remain byte-compatible v1; a reference-bound contract uses the
  additive `jstack.ui.contract.v2` / `ui-contract.v2.schema.json` successor.
- Added a dependency-free host-orchestration workflow inspired by
  `abi/screenshot-to-code` at pinned commit
  `d026163f586dfa8c5c10d28c36edd59a9d3b0e88`; no upstream application runtime
  or provider SDK is vendored.

### Changed

- Advanced all public version-bearing plugin and MCP identities to
  `0.10.0-beta.3`. The dedicated layout now contains six command plugins and
  the live MCP exposes 56 canonical `jstack_*` tools while the 52 legacy
  `gstack_*` aliases remain byte-compatible and frozen.
- Kept ordinary reference-free Product Interface contracts byte-compatible as
  `jstack.ui.contract.v1`; only contracts carrying a finalized reference
  binding use the additive `jstack.ui.contract.v2` successor.

### Security

- Reference artifacts remain beneath a server-selected private root and are
  descriptor-, size-, media-, dimension-, and digest-validated. URL authority,
  rights basis, redaction state, and external-provider use are explicit.
- Reference receipts are provenance evidence only. They grant no project-write,
  candidate-QA, security, release, deployment, legal, or production authority.
- This prerelease does not validate the deferred Beta.1 Proof Study and makes
  no measured uplift, superiority, stable-release, or production-readiness
  claim.

## 0.10.0-beta.2 - 2026-08-15 - Product Interface prerelease

### Added

- Added the JStack Product Interface System and automatically routed its
  `product-ui-design` skill for user-facing interface work inside the existing
  five commands; backend-only work remains unaffected and no sixth slash
  command was added.
- Added the original `editorial-calm` and `creative-canvas` profiles, hybrid
  shell/workspace composition, greenfield light/dark coverage, a 4px spacing
  base, restrained 4–12px radii, 1px separators, zero negative letter spacing,
  and 120/180/240ms purposeful motion defaults.
- Added deterministic precedence for explicit user direction, an existing
  project design system, the applicable domain profile, and the editorial
  fallback. Existing tokens, components, accessibility rules, layouts, and
  brand constraints are preserved and extended unless redesign is explicit.
- Added the separate versioned Product Interface catalog and the canonical-only
  `jstack_ui_contract` and `jstack_ui_finalize` tools. The live Beta.2 surface
  is 54 canonical `jstack_*` tools plus the frozen 52 legacy `gstack_*`
  aliases; no legacy UI aliases were introduced.
- Added Git-bound UI contract/finalization evidence, exact QA/build/runtime
  binding, a complete viewport/state/theme/platform PNG matrix, objective
  adapter checks, Product Designer observations, UI receipt propagation through
  planning, team, loop, program, and release-readiness workflows, and a
  catalog-bound read-only Product Interface review for JStack Audit.
- Added adapters for web, webview, iOS, Android, React Native, Flutter,
  Electron, Tauri, macOS, Windows, and Linux. Web ships with a qualified
  evidence contract; webview, packaged-shell, native, and cross-platform
  adapters are explicitly contract-only pending exact-runtime provenance
  evidence.
- Added transactional installation of exactly one Product Interface skill.
  Direct installs may opt in to a bounded managed global `AGENTS.md` block with
  `--manage-agents`; the default preserves global instructions unchanged, and
  enabled plugin copies prevent a duplicate direct installation.
- Added ADR 0023 and the Beta.2 migration guide covering design intent,
  originality, activation, evidence, compatibility, installation, limitations,
  and rollback.
- Added six non-authorizing representative Product Interface evaluation tasks
  and a provider-blind review rubric covering hierarchy, coherence,
  responsiveness, accessibility, platform fit, and generic-AI styling risks;
  these fixtures are separate from the frozen Beta.1 Proof Study.

### Changed

- Advanced public installable metadata and the live MCP candidate identity to
  `0.10.0-beta.2` while preserving five command plugins, Python 3.9+, the
  standard-library core, compatible Beta.1 non-UI requests, exact declared
  UI-aware successor fields, and readable v1 loop/program state for non-UI
  work.
- Added the optional exact `capability_selection_digest` successor field to
  specialist result and handoff inputs. Product Interface plans propagate that
  digest so generic or full-team goals cannot be rebound to an ordinary
  capability plan with the same role roster; existing non-UI calls remain
  accepted without it.
- Kept the development-only Beta.1 Proof Plane byte-frozen and unvalidated at
  the exact annotated `v0.10.0-beta.1` tag. CI now fetches full Git history and
  exports that tag's 52-tool MCP tree for the Proof runtime probe rather than
  substituting the live Beta.2 server.

### Security

- Product Interface evidence uses a fixed server-selected private root,
  bounded strict manifests, descriptor-safe file reads, exact artifact hashes,
  validated PNG structure, critical-surface observations, and clean strict
  baseline-to-candidate Git ancestry.
- UI contract envelopes use a dedicated private per-user POSIX signing key so
  exact in-flight contracts can be finalized after an MCP restart; freshness
  is still required for new loop/program intake, all other receipts remain
  session-local, and Windows retains session-local UI contracts rather than
  persisting a key without verifiable DACL/reparse guarantees. Windows UI
  evidence finalization also fails closed until those private-file guarantees
  can be established; routing and contract planning remain portable.
- UI receipts are evidence only. They never replace QA, security, audit,
  launch, release-owner approval, provider controls, or explicit deployment
  scope. Screenshots prove validated bytes and declared coverage, not capture
  honesty, runtime provenance, subjective visual excellence, or user
  preference; human aesthetic approval remains optional and is never inferred.
- The visual direction is an original implementation influenced by calm
  editorial hierarchy and focused creative-workspace qualities associated with
  products such as Claude and Fable. It copies no proprietary theme, layout,
  asset, branding, or source code and implies no affiliation or endorsement.
- Beta.2 publication does not validate the deferred Beta.1 18-image,
  216-attempt, 432-review study and enables no measured uplift, superiority,
  stable-release, production-readiness, or universal UI-quality claim.

## 0.10.0-beta.1 - 2026-08-15 - Unvalidated prerelease

### Added

- Added the uninstalled Beta.1 Proof Plane maintainer lifecycle for sealed
  image construction and qualification, task-artifact curation and baseline
  reproduction, immutable 216-cell admission and execution, delayed holdout
  grading, signed blinded review, evidence assembly, and independent final
  verification.
- Added exact six-family, 18-task public briefs plus source, image, runtime,
  holdout, reviewer, controller, grader, and evidence contracts with
  fail-closed recovery and atomic publication rules.
- Added Apple container host/runtime TCB inspection, OCI/rootfs inspection,
  guest execution-TCB binding, immutable image-store observations, signed
  builder provenance, and dedicated task-artifact lifecycle evidence.
- Added a fixed fresh-root Apple runtime bootstrap lifecycle and a deterministic,
  non-authorizing preregistration-candidate builder with crash-safe private and
  public publication receipts. Neither surface installs the runtime, creates a
  tag, starts a study attempt, or publishes a release implicitly.
- Added the Beta.1 migration and rollback guide, ADR 0021's validation
  contract, and ADR 0022's explicit unvalidated-prerelease distribution
  boundary.

### Changed

- Advanced every installable version-bearing artifact and MCP initialize
  response to `0.10.0-beta.1` while retaining five commands, 52 canonical
  tools, Python 3.9 compatibility, the standard-library core, and alpha.9
  public-contract compatibility.
- Kept the Proof Plane outside installed MCP and plugin artifacts. Product
  synchronization and boundary checks reject any accidental packaging of
  private study authority.
- Tightened live preregistration and attempt admission to bind the MCP server
  version as well as its exact bytes and 52-tool surface.

### Security

- This prerelease is not a validated study result. The 18 image
  qualifications, 216 attempts, 432 independent human reviews, final evidence
  signature, scoring, and validated/stable promotion remain deliberately
  deferred and cannot be inferred from publication, installation, or passing
  product tests.
- No test fixture, self-digest, model-authored review, or partial study output
  can satisfy the accepted Beta.1 validation gate.

## 0.10.0-alpha.10 - 2026-08-12

### Added

- Added a development-only `evals/` Proof Plane outside the installed MCP and
  plugin payloads, with closed v1 corpus, task, run-envelope, blinded-review,
  and score contracts.
- Added a deterministic, standard-library-only mock host and scorer that
  reports raw counts, Wilson 95% intervals, task completion, vulnerability
  recall, correct-patch rate, false findings, clean-case false blockers,
  regressions, line/branch/mutation deltas, cost, time, human-review escapes,
  verified risks intercepted before merge, and paired JStack uplift.
- Added a public development manifest for TypeScript/web, Python APIs,
  Java/C# services, C/C++ systems, data/database projects, and legacy
  repositories. It declares three planned task kinds per family without
  claiming that the 18 real-project tasks or results already exist.
- Added a raw-byte corpus lock, deterministic mock fixture, adversarial
  contract tests, and explicit privacy/claim boundaries.
- Added manifest-bound execution plans that reject missing or extra runs;
  public plans require all 18 family/task-kind slots, both comparison modes,
  exact plain/JStack pairs, and at least three repetitions per condition.
- Added an alpha.9 public-contract snapshot covering the five commands, 52
  canonical MCP request schemas, 52 legacy aliases, published core schemas,
  persisted-state markers, plugin layouts, protocol versions, roles,
  capabilities, and launch-catalog counts.
- Added CI-enforced contract-compatibility and permanent product-boundary
  checks.

### Changed

- Corrected the release checklist template to use explicit conversational
  scope and ordinary host/provider controls. Retired challenge, token, signer,
  permit-mailbox, and terminal-paste fields were removed.
- Development verification now compiles `evals/`, verifies the Proof Plane
  lock, checks alpha.9 compatibility, and enforces five commands, 52 canonical
  tools, 11 roles, 18 capability packs, 47 launch controls, a standard-library
  core, and exclusion of Proof Plane files from installed artifacts.
- Increased the MCP transport timeout from 300 to 1,900 seconds across direct
  and umbrella installations. This covers the longest permitted 1,800-second
  capture plus bounded receipt overhead; workflow command budgets remain
  independently bounded.
- Preserved the installed runtime and all existing tool request contracts; the
  release adds no command, MCP tool, vendor SDK, runtime dependency, scanner,
  network importer, role, or external authority.

### Security

- Failed, blocked, and timed-out benchmark runs cannot be removed from scoring.
  Controlled pairs must use identical task, host-model-JStack, image,
  toolchain, allowed-tool, tool-call-limit, repetition, and budget bindings;
  every run requires exactly two unique independent blinded reviewers, with a
  distinct third adjudicator only for disagreement.
- Correct-patch credit requires completed, untruncated, blocker-passing,
  regression-free execution. Rate intervals are recomputed from raw counts,
  and paired uplift uses a conservative distribution-free interval rather than
  reporting false certainty from small identical samples.
- Run envelopes prohibit source, prompts, model output, command output, and
  human identity. The mock runner performs no project execution, network
  access, source fetch, model call, or filesystem mutation.
- Alpha.10 mock results prove protocol determinism only. They are not evidence
  of real-project performance, host superiority, universal zero-day detection,
  professional-grade output, or production readiness.

## 0.10.0-alpha.9 - 2026-08-10

### Added

- Implemented Audit mastery Stage 8, Enterprise Audit Lead, as the ninth
  bounded foundation phase.
- Added the closed `jstack.audit.enterprise-risk-register.v1` contract and
  published `audit-enterprise-risk-register.v1.schema.json`.
- Added exact reconciliation across the current signed release-audit receipt,
  finalized `jstack.audit.result.v1`, deterministic SARIF 2.1.0, canonical
  engineering/executive Markdown, and a priority-first risk register.
- Added deterministic current-finding coverage, open-risk owner/reason/target
  dates, exact accepted-risk owner/reason/approval/expiry/control fields,
  derived go/no-go logic, and metadata-only Stage 8 evaluation records.
- Added a committed controls drill that requires a strict ancestor, exact Git
  diff, a Git-immutable baseline audit result matching a prior passed Stage 8
  attempt, at least one verified remediated fingerprint, a passing current
  release audit, and no introduced blocker, severity increase, or priority
  escalation.
- Added adversarial tests for altered SARIF, wrong release decisions, invalid
  risk ownership, unvalidated baselines, non-training drift, exact receipt
  reconciliation, verified remediation, schema binding, advancement, and
  Windows CRLF portability.

### Changed

- Audit curriculum content version is now 10. Stage 8 advancement requires
  three independent deterministic passes across at least two commits, every
  score at least 80, a mean score of at least 85, and both Stage 8 drills.
- Stage 8 permits only `audit-report.md`, `audit-result.json`, `audit.sarif`,
  and `risk-register.json` at their exact `.jstack-training/` paths.
- The current audit receipt may differ from the mastery-record project
  fingerprint only because the four exact Stage 8 outputs are written after
  audit finalization; every other dirty path fails closed.
- Stage 8 compares canonical Markdown across LF and CRLF checkouts and binds a
  prior baseline by its commit plus canonical JSON SHA-256, while exact current
  artifact bytes remain independently digest-bound.
- Preserved the five commands, 52 canonical tools, mastery profile v3, Python
  3.9+ standard-library runtime, cross-platform packaging, and token-free
  host-native action model.

### Security

- Stage 8 requires a fresh current-session, exact-HEAD, repository-scope,
  release-profile, complete Git audit receipt. Receipt coverage, finding,
  count, suppression, threshold, status, and evaluation-time fields must match
  the retained finalized result exactly.
- Rejected, duplicate, stale, malformed, wrong-scope, future-created, or
  expired suppressions fail closed. Accepted risk remains explicit human
  governance evidence and is never silently inferred by JStack.
- Audit remains read-only: it cannot implement remediation or controls, accept
  risk for a human, change Git, publish, release, deploy, or access production.
- A Stage 8 pass proves evidence-contract, report-projection, decision, and
  baseline/candidate comparison integrity only. It does not prove
  vulnerability absence, exploitability, zero-day detection, standards
  compliance, release authorization, or production safety.

## 0.10.0-alpha.8 - 2026-08-09

### Added

- Implemented Audit mastery Stage 7, Dynamic and Adversarial Verification
  Auditor, as the eighth bounded foundation phase.
- Added closed `jstack.adversarial.capture.v1` and
  `jstack.audit.adversarial-verification.v1` contracts and published schemas.
- Added `jstack_adversarial_capture`, the 52nd canonical MCP tool, for bounded
  deterministic evidence capture through one discovered command at an exact
  reviewed Git state. It binds the campaign, plan, deterministic corpus and
  seed, target scope, command, environment, case-set digest, outcome-set
  digest, policy, version, and current server session without a user token or
  terminal-paste ceremony.
- Added exact reconciliation for eight adversarial categories, two-run outcome
  determinism, reciprocal case/hypothesis ownership, static and dynamic
  origins, confirmed and refuted dispositions, and one supported or
  false-positive assessment per hypothesis.
- Added strict audit-versus-harness drill semantics. The audit drill uses one
  current capture; the harness drill verifies a separately committed strict-
  ancestor diff with exact changed paths, at least one added case, no removed
  cases, and stable shared contracts and outcomes.
- Added adversarial tests for nondeterministic and duplicate cases, weak
  coverage, stale trust bindings, capture/report tampering, incomplete false-
  positive reciprocity, non-training writes, QA/security binding, schema/tool
  registration, and Stage 7 advancement.

### Changed

- Audit curriculum content version is now 9. Stage 7 advancement requires
  three independent deterministic passes across at least two commits, every
  score at least 80, a mean score of at least 85, and both named Stage 7
  drills.
- Stage 7 permits only `adversarial-plan.md`, `verification-results.json`, and
  `false-positive-analysis.md` at their exact `.jstack-training/` paths.
- Both Stage 7 drills require current passing receipts for every discovered QA
  command plus a current complete passing security receipt.
- Preserved the five commands, mastery profile v3, Python 3.9+ standard-library
  runtime, cross-platform packaging, and token-free host-native action model.

### Security

- The deterministic evaluator executes no repository code, implements no
  harness or exploit, creates no candidate, accesses no secrets, and performs
  no remediation or production action. Dynamic captures remain separately
  authorized trusted development/QA actions bound to exact project state.
- Capture artifacts exclude raw inputs, payloads, source, secrets, stdout, and
  stderr. Only bounded identifiers, classifications, counts, and SHA-256
  digests cross the receipt boundary; malformed, stale, failed, mutated,
  duplicate, mismatched, wrong-session, or unused evidence fails closed.
- Local capture uses a scrubbed environment, isolated HOME, closed stdin,
  process-group timeouts, and output caps, but it is not an OS or network
  sandbox. `none-observed` is not enforced isolation, and untrusted or active
  testing requires an external container or VM plus target authorization.
- A Stage 7 pass proves bounded evidence-protocol integrity only. It does not
  prove vulnerability absence, exploitability, zero-day detection, universal
  behavior, remediation safety, release readiness, production safety, or
  production authority.

## 0.10.0-alpha.7 - 2026-08-09

### Added

- Implemented Audit mastery Stage 6, Supply-Chain, Build and Release-Integrity
  Auditor, as the seventh bounded foundation phase.
- Added closed `jstack.audit.dependency-inventory.v1` and
  `jstack.audit.supply-chain-report.v1` contracts and published schemas.
- Added deterministic exact-Git discovery for tracked dependency manifests,
  lockfiles, policies, build configurations, GitHub workflows, provenance
  files, and conventional generated artifacts across major language
  ecosystems.
- Added closed parsing and reconciliation for every GitHub Actions `uses:`
  reference and top-level permission declaration, build graph and material
  provenance validation, generated-copy drift recomputation, exact QA
  coverage, and strict-ancestor hardening diffs.
- Added a curated cross-ecosystem `osv-scanner-offline` dependency analyzer.
  It is available only when the OSV executable and an external local advisory
  database directory are present; the exact executable, database path,
  command, environment, project subject, and result are receipt-bound.
- Added adversarial coverage for omitted inventory inputs, dynamic or mutable
  action references, permission gaps, hidden or misclassified generated drift,
  malformed relationships, stale or tampered scanner receipts, non-training
  writes, schema/curriculum binding, and Stage 6 advancement.

### Changed

- Audit curriculum content version is now 8. Stage 6 advancement requires
  three independent deterministic passes across at least two commits, every
  score at least 80, a mean score of at least 85, and both the static audit and
  committed-hardening verification drills.
- Final Git-bound audit receipts now include only bounded sanitized adapter
  result metadata so Stage 6 can verify same-session dependency-analysis
  evidence without retaining scanner output or secrets.
- Stage 6 permits only `dependency-inventory.json`, `build-trace.md`, and
  `supply-chain-report.json` at their exact `.jstack-training/` paths.
- Both Stage 6 drills require current passing receipts for every discovered
  JStack QA command. Dependency evidence never substitutes for correctness
  evidence.
- Preserved the five commands, 51 canonical MCP tools, mastery profile v3,
  Python 3.9+ standard-library runtime, cross-platform packaging, and
  token-free host-native action model.

### Security

- The evaluator executes no repository code, resolves no packages, contacts no
  registry, accesses no secrets, and performs no hardening. Dependency scans
  remain separately approved curated adapter actions bound to exact project
  state; incomplete, failed, mutated, stale, or mismatched results fail closed.
- Dynamic or unparseable GitHub Actions references are rejected. Mutable
  references, implicit/unsupported/unbounded CI permissions, missing
  provenance, and generated drift must be represented by verified findings.
- OSV execution enforces the scanner's offline mode and rejects a missing,
  unreadable, or repository-contained advisory database directory. Local
  process isolation remains outside JStack's standard-library runner.
- Local curated-adapter execution is not an OS or network sandbox. A Stage 6
  pass proves bounded protocol integrity only; it does not prove complete
  transitive dependencies, current advisory coverage, reproducible builds,
  artifact authenticity, vulnerability absence, release readiness, or
  production authority.

## 0.10.0-alpha.6 - 2026-08-05

### Added

- Implemented Audit mastery Stage 5, Performance and Resource-Efficiency
  Auditor, as the sixth bounded foundation phase.
- Added closed `jstack.performance.capture.v1`,
  `jstack.audit.performance-results.v1`, and
  `jstack.audit.performance-findings.v1` contracts and published schemas.
- Added `jstack_performance_capture`, the 51st canonical MCP tool, for bounded
  discovered-command measurement in separately authorized trusted developer
  or QA workflows. It signs exact Git, workload, command, local-environment,
  sample, policy, version, and server-session bindings without any user token
  or terminal-paste ceremony.
- Added deterministic recomputation of retained-sample summaries,
  nearest-rank percentiles, budget violations, candidate improvement, and
  guardrail regressions, with exact historical-baseline/current-candidate
  receipt verification.
- Added adversarial coverage for capture protocol, signature and workload
  tampering, fabricated summaries and percentages, guardrail regressions,
  exact Git diff and QA binding, metadata-only results, advancement, schemas,
  and tool registration.

### Changed

- Audit curriculum content version is now 7. Stage 5 advancement requires
  three independent deterministic passes across at least two commits, every
  score at least 80, a mean score of at least 85, and both the measurement-only
  audit and committed-remediation verification drills.
- Stage 5 permits only `benchmark-plan.md`, `baseline-results.json`, and
  `performance-findings.json` at their exact `.jstack-training/` paths.
- Both Stage 5 drills require current passing JStack QA. Performance evidence
  never substitutes for correctness evidence.
- Updated the Audit skill, prompt, architecture, security policy, mastery
  guide, installation guide, migration guide, and release documentation for
  the new signed measurement boundary.
- Preserved the five commands, mastery profile v3, Python 3.9+ standard-library
  runtime, cross-platform packaging, and token-free host-native action model.

### Security

- Audit never invokes the performance runner or edits the target. Capture
  execution is a separate exact-trust developer/QA action using a scrubbed
  environment, isolated HOME, fixed external output file, no forwarded
  secrets, no shell, bounded process output/time, and Git-visible tracked or
  non-ignored mutation detection. Ignored cache/build outputs remain outside
  that guarantee.
- Performance output is identity-checked, bounded, duplicate-key rejected,
  secret-screened, and normalized to finite non-negative samples. Command
  stdout and stderr are reduced to digests and not returned.
- The local runner is not an OS or network sandbox. A Stage 5 pass proves
  bounded protocol integrity only; it does not prove workload realism,
  measurement accuracy, universal performance, production capacity,
  correctness, optimization safety, release readiness, or production
  authority.

## 0.10.0-alpha.5 - 2026-08-05

### Added

- Implemented Audit mastery Stage 4, Maintainability and Architecture Auditor,
  as the fifth bounded foundation phase.
- Added the closed `jstack.audit.maintainability-report.v1` contract and
  published schema for exact baseline/candidate Git commit and tree binding,
  six-surface architecture coverage, revision-bound source evidence,
  components, dependency direction, contracts, change-amplification
  scenarios, material findings, remediations, compatibility assessments,
  current QA bindings, gaps, boundaries, and limitations.
- Added deterministic evaluation for static architecture audits and for one
  separately authorized, committed, behavior-preserving remediation, including
  exact Git-diff reconciliation and current JStack QA receipt verification.
- Added adversarial tests for stale revisions, weakened boundaries, schema and
  artifact-binding drift, style-only findings, unsupported coverage, broken
  graph relationships, incorrect change-amplification counts, unsafe evidence,
  secret-like values, narrative TOCTOU, compatibility breaks, fabricated QA,
  non-training changes, advancement, and curriculum/schema binding.

### Changed

- Audit curriculum content version is now 6. Stage 4 advancement requires
  three independent deterministic passes across at least two commits, every
  score at least 80, a mean score of at least 85, and both the architecture
  audit and remediation-verification drills.
- Stage 4 permits only `architecture-map.md`,
  `maintainability-report.json`, and `migration-outline.md` at their exact
  `.jstack-training/` paths.
- Updated Audit workflow guidance to distinguish an Audit-authored proposal
  from evidence about a candidate changed and committed by a separately
  authorized development workflow.
- Preserved the five commands, 50 canonical MCP tools, read-only Audit
  boundary, mastery profile v3, Python 3.9+ standard-library runtime,
  cross-platform packaging, and token-free host-native action boundary.

### Security

- The Stage 4 evaluator treats repository content as untrusted data, reads
  source evidence only from immutable Git objects, executes no repository
  code, performs no network or secret access, and writes no application code.
- Audit attempts require baseline and candidate to be the same current
  revision and may contain proposals only. Implementation attempts require a
  strict ancestor baseline, the exact committed candidate diff, explicit
  compatibility evidence, and a current passing JStack QA receipt.
- A Stage 4 pass proves deterministic architecture-evidence and receipt
  integrity only. It does not prove semantic correctness, behavior
  preservation, maintainability, compatibility, vulnerability absence,
  remediation safety, release readiness, or production authority.

## 0.10.0-alpha.4 - 2026-08-05

### Added

- Implemented Audit mastery Stage 3, Security and Threat-Modelling Auditor, as
  the fourth bounded foundation phase.
- Added the closed `jstack.audit.security-findings.v1` contract and published
  schema for exact Git HEAD/tree binding, complete STRIDE coverage,
  hash-verified source evidence, assets and CIA objectives, bounded
  adversaries, trust boundaries, controls, reciprocal abuse cases and attack
  paths, findings, pinned standards mappings, gaps, completeness, boundaries,
  and limitations.
- Added deterministic validation for verified reachable blocker paths,
  critical seeded findings, strong-claim confidence, object/reference use and
  reciprocity, narrative hashes, UTF-8 and secret safety, and metadata-only
  results.
- Added adversarial tests for stale subjects, weakened safety boundaries,
  binding drift, unsupported coverage, gaps, speculative high severity,
  conditional blockers, standards drift, broken reciprocity, unused objects,
  secret-like JSON and narratives, narrative TOCTOU, unsafe/untracked
  citations, non-training changes, advancement, and curriculum/schema binding.

### Changed

- Audit curriculum content version is now 5. Stage 3 advancement requires two
  consecutive independent attempts scoring at least 80 and passing every
  deterministic threat-model gate.
- Stage 3 permits only `threat-model.md`, `security-findings.json`, and
  `abuse-cases.md` at their exact `.jstack-training/` paths.
- Pinned applicable mapping syntax to MITRE CWE 4.20, NIST SP 800-218 v1.1,
  OWASP ASVS 5.0.0, and OWASP Top 10:2025.
- Preserved the five commands, 50 canonical MCP tools, read-only Audit
  boundary, mastery profile v3, Python 3.9+ standard-library runtime,
  cross-platform packaging, and token-free host-native action boundary.

### Security

- Stage 3 is static-only. It performs no repository execution, live
  exploitation, network or secret access, exploit-payload retention,
  remediation, unsafe publication, release, deployment, or production action.
- JSON and both bound narratives reject recognized secret-like values; source
  citations must be current tracked regular files with bounded lines and exact
  SHA-256 hashes.
- A Stage 3 pass proves deterministic structure, binding, traceability, and
  safety-contract compliance only. It does not prove vulnerability absence,
  exploitability, zero-day detection, semantic truth, standards compliance,
  remediation safety, release readiness, or production security.

## 0.10.0-alpha.3 - 2026-08-03

### Added

- Implemented Audit mastery Stage 2, Correctness and Reliability Auditor, as
  the third bounded foundation phase.
- Added closed `jstack.audit.correctness-report.v1` and
  `jstack.audit.correctness-reproductions.v1` contracts for exact Git
  HEAD/tree binding, four-surface coverage, current source-line evidence,
  invariants, findings, reproductions, regression plans, gaps, completeness,
  exact boundaries, and limitations.
- Added deterministic validation for static invariant counterexamples and for
  executed reproductions backed by a passing current exact-revision
  `jstack_qa` receipt with matching command identity and return code.
- Added adversarial tests for stale subjects, false boolean aliases, unknown
  fields, missing coverage, stale hashes, gaps, incomplete packages,
  unverified or speculative blockers, fabricated QA bindings, raw output or
  extra reproduction files, unsafe/untracked citations, non-training changes,
  advancement, and curriculum/schema binding.

### Changed

- Audit curriculum content version is now 4. Stage 2 advancement requires two
  consecutive independent attempts scoring at least 80 and passing every
  deterministic correctness-evidence gate.
- Audit mastery Stage 2 may write only `correctness-report.json`,
  `invariants.md`, and `reproductions/manifest.json` under
  `.jstack-training/`; any other dirty path hard-blocks the attempt.
- Every verified finding requires a regression plan covering before-fix,
  after-fix, unrelated-behavior, and failure-state checks. Every blocker or
  high/critical claim must also be verified, high-confidence, reachable or
  conditional, and linked reciprocally to a violated invariant and a
  reproduction.
- Preserved the five commands, 50 canonical MCP tools, read-only Audit
  boundary, mastery profile v3, Python 3.9+ standard-library runtime,
  cross-platform packaging, and token-free host-native action boundary.

### Security

- Stage 2 binds both evidence documents and every source citation to the exact
  committed subject and rejects stale, malformed, secret-like, unused,
  unsupported, incomplete, or fabricated evidence without echoing raw source
  or reproduction content.
- Static proofs avoid repository execution. Executed cases must reuse current
  JStack QA evidence; JStack QA remains environment hardening rather than an OS
  or network sandbox, so untrusted execution still requires an externally
  enforced container or VM.
- A Stage 2 pass proves deterministic evidence-contract compliance only. It
  grants no remediation, Git, release, deployment, production, vulnerability-
  absence, zero-day-detection, or semantic-completeness claim.

## 0.10.0-alpha.2 - 2026-08-02

### Added

- Implemented Audit mastery Stage 1, Repository Reconnaissance and System
  Mapping, as the second bounded security-remediation foundation phase.
- Added the closed `jstack.audit.repository-map.v1` contract and published
  JSON Schema for exact Git HEAD/tree binding, eight-surface coverage,
  hash-verified source-line evidence, nodes, flows, trust boundaries,
  generated-artifact provenance and drift risk, gaps, completeness, and exact
  limitations.
- Added deterministic Stage 1 evaluation metadata, failure codes, counts, and
  evaluation digests without returning raw map or repository content.
- Added adversarial coverage for stale subjects, non-boolean aliases, unknown
  fields, missing surfaces, stale hashes, dangling graph references, explicit
  gaps, unsafe and untracked citations, non-training changes, generated-copy
  provenance, advancement, installation, and curriculum/schema binding.

### Changed

- Audit curriculum content version is now 3. Stage 1 advancement requires two
  consecutive independent attempts scoring at least 80 and passing every
  deterministic repository-map gate.
- Audit mastery may write only the three declared Stage 1 artifacts beneath
  `.jstack-training/`; any other changed path hard-blocks the attempt.
- Updated the Audit skill, prompt, architecture, security policy, mastery
  guide, plugin metadata, installer expectations, and migration guidance for
  `v0.10.0-alpha.2`.
- Preserved the five commands, 50 canonical MCP tools, mastery profile v3,
  Python 3.9+ standard-library runtime, and token-free host-native action
  boundary.

### Security

- Stage 1 treats repository content as untrusted data and permits no
  repository execution, network access, secret access, Git mutation,
  remediation, external action, or production access.
- Evidence reads are descriptor-confined and capped. Citations must reference
  tracked regular files outside `.git` and `.jstack-training`, fit valid line
  ranges, and match the current SHA-256.
- Unsupported coverage, unresolved gaps, incomplete maps, stale bindings,
  unused evidence, malformed fields, graph inconsistencies, and missing
  generated-artifact provenance fail closed.
- A Stage 1 pass proves structural and citation-contract compliance only; it
  does not prove semantic completeness, vulnerability absence, zero-day
  detection, exploitability, remediation, or production readiness.

## 0.10.0-alpha.1 - 2026-08-01

### Added

- Added Audit mastery Stage 0, **Safe Security Operator**, as the first
  implementation slice of the planned verified security-remediation program.
- Added two inert required labs: hostile-repository instruction handling and
  suspected novel-vulnerability private-disclosure handling.
- Added the closed
  `jstack.audit.security-orientation.v1` artifact contract and deterministic
  MCP evaluation with named failure codes and a content-free evaluation
  digest.

### Changed

- Advanced the audit curriculum content version to 2. Stage 0 now requires the
  two distinct named labs as the latest two independent attempts, each scoring
  at least 80 and passing the deterministic safety contract.
- Preserved the guided `a0-orientation` drill for practice, but it cannot
  satisfy Stage 0 advancement. Existing completed audit stages and profile v3
  state remain intact.
- Updated Audit workflow, mastery, architecture, security, migration, and
  installation guidance for the new boundary.

### Security

- Stage 0 treats every repository instruction as untrusted data and prohibits
  repository execution, network access, secret access, exploit development,
  public exploit or suspected novel-vulnerability disclosure, production
  access, and writes outside `.jstack-training/`.
- Malformed or extended orientation artifacts fail closed. Structurally valid
  but unsafe decisions become hard-gate failures, and raw submitted content is
  not echoed in the attempt result.
- Passing Stage 0 grants no execution, remediation, publication, merge,
  release, deployment, or production authority. No command, role, MCP tool,
  approval token, terminal ceremony, or permission was added.

### Preview scope

- This prerelease implements Stage 0 only. It does not yet add repository-wide
  vulnerability remediation, zero-day detection claims, exploit verification,
  scanner orchestration, differential testing, sandbox provisioning, patch
  generation, CI pull requests, or production release automation.

## 0.9.1 - 2026-07-31

### Added

- Added the Adaptive Context Gate across all five existing JStack workflows.
  It inspects project context first, separates sourced facts from assumptions,
  asks at most three material questions per round, and includes a reason and
  recommended default for every question.
- Added `jstack_context_readiness` and the
  `jstack.context-readiness.v1` schema. Ready results issue privacy-minimized,
  session-local planning receipts bound to the exact goal, workflow, project,
  tool version, and current Git state when available.
- Added adversarial coverage for clear prompts, vague product prompts,
  high-risk defaults, source attribution, artifact-only planning, audit-safe
  defaults, privacy minimization, stale Git state, and Loop compatibility.

### Changed

- Dev, Subagents, Full Team, and Audit now pass the context-readiness receipt
  plus its digest-verified normalized brief into their planning or audit
  contracts, keeping sourced facts and assumptions visible. Loop and Program reuse their stronger
  goal-readiness contracts and now include reasons and recommended defaults in
  their bounded questions rather than running a duplicate intake round.
- Low-risk work can continue with visibly disclosed recommended assumptions.
  Security, financial, legal, destructive, migration, and production-critical
  material defaults remain fail-closed until explicit in-conversation
  confirmation.
- Increased the canonical MCP inventory from 49 to 50 tools without adding a
  sixth slash command or changing staffing authority.

### Security

- Context receipts store only structured digests and binding metadata, never
  raw prompts, messages, source contents, user answers, or secrets.
- Caller-supplied risk tiers cannot lower a goal below its derived floor;
  high-risk material assumptions and inferred facts fail closed. Audit receipts
  bind explicitly supplied profile, scope, focus, and base selectors.
- The gate uses normal conversation only. It adds no approval challenge,
  signer, token, digest-paste request, mailbox, or terminal command.

## 0.9.0 - 2026-07-26

### Added

- Added Launch Assurance v2: a deterministic 47-control catalog across
  security, email, findability, speed, analytics, legal, and final-test
  categories, selected from 22 explicit product and risk surfaces.
- Added four risk tiers with non-lowerable surface and policy floors. High-risk
  security controls become blockers; critical required controls become
  blockers; critical launches cannot use waivers.
- Added bounded static surface-hint detection and accountable reconciliation
  for detected-but-omitted surfaces without returning source content.
- Added composite evidence requirements, exact deployment-fingerprint binding,
  native structured evidence, provider-neutral scanner JSON, SARIF 2.1.0
  normalization, and published v2 schemas.
- Added mandatory independent scanner evidence at high risk and independent
  scanner plus human security-review evidence at critical risk.

### Changed

- JStack now derives launch outcomes from required assertions. Caller-written
  outcomes, verifier prose, summaries, READMEs, and arbitrary files can no
  longer satisfy a launch control.
- Database authorization now requires both effective-policy evidence and
  anonymous/cross-tenant negative probes. Cost controls, CORS, CSRF,
  authentication, data governance, license provenance, and hostile-input
  checks remain distinct composite gates.
- Launch, loop, program, and release-readiness receipts now bind the risk tier,
  deployment fingerprint, detected surface digest, reconciliation digest, and
  complete per-requirement result set.
- Upgraded all five existing JStack commands without adding another command or
  reintroducing approval tokens.

### Security

- External scanner parsing is audit-owned, bounded, target-matched,
  completeness-aware, and provider-neutral. Truncated scans, wrong targets,
  non-independent producers, and unresolved high or critical findings fail
  closed.
- High- and critical-risk security controls cannot be waived. Critical risk
  requires an independently produced human security-review artifact in
  addition to scanner output.
- Launch receipts still prove evaluated evidence and exact subject binding, not
  producer honesty, legal sufficiency, penetration-test completeness, or facts
  outside the observed scope.

## 0.8.2 - 2026-07-24

### Removed

- Removed the JStack external-action challenge, authorize, consume, HMAC
  signer, private mailbox, identity template, schemas, policy floor, and
  generated artifacts.
- Removed the signed program-gate challenge, signer, identity configuration,
  and token input.

### Changed

- Human program gates now record an explicit conversational decision directly
  through `jstack_program_gate_resolve`, bound to the current program, gate,
  required role, reference digest, freshness window, and decision digest.
- External operations now rely on explicit user scope and normal Codex/provider
  permissions. JStack never asks for an approval token or terminal command.
- Existing v0.8.1 policy files remain loadable; retired custom-approval fields
  are ignored with a migration warning.
- Reduced the canonical MCP inventory from 53 to 49 tools and the Program tool
  family from 14 to 13 tools.

### Security

- Read-only Audit, protected-path checks, QA/security receipts, launch
  assurance, release evidence, rollback/monitoring requirements, exact
  project-state binding, and provider-side protection guidance remain.
- Conversational human-gate records are explicitly documented as auditable
  caller-supplied decisions, not cryptographic identity, SSO, or
  non-repudiation.

## 0.8.1 - 2026-07-22

### Added

- Added a private local approval mailbox for every protected external action.
  Challenges now create owner-only request files and return a short
  `jstack-approve` command; the independently run helper writes an owner-only
  response that JStack collects automatically.
- Added versioned approval-request and approval-response schemas plus
  adversarial coverage for missing responses, unsafe permissions, transport
  compatibility, automatic cleanup, and zero-token-output behavior.

### Changed

- `jstack_external_action_authorize` now needs only `project_path` and
  `authorization_id` for the default flow. Inline `approval_attestation`
  remains available only as a compatibility transport.
- Updated all write-capable JStack workflows to ask the named human to run the
  displayed local approval command and never request that a token be pasted
  into chat.

### Security

- Human approval remains independent, exact-action, short-lived, role-bound,
  session/Git/remote/target-bound, and one-time. The helper requires an
  interactive `APPROVE ONCE` confirmation unless the full digest is supplied
  non-interactively, never prints the signed capability in mailbox mode, and
  stores it in a `0600` response removed after successful authorization.
- The no-copy transport does not turn broad task approval into authority and
  does not let Codex run the approver command, access the private key, retry a
  consumed action, or bypass provider observation and one-time consumption.

## 0.8.0 - 2026-07-22

### Added

- Added a versioned 37-control launch catalog across security, email,
  findability, speed, analytics, legal, and final-test categories, selected
  from 14 explicit product surfaces.
- Added `jstack_launch_assess`, `jstack_launch_evidence_register`, and
  `jstack_launch_finalize` for clean-candidate profile binding, bounded
  content-free artifact identity, typed expiring outcomes, fail-closed
  aggregation, and signed release-consumable receipts.
- Added launch catalog, evidence, and result schemas; enterprise policy floors;
  ADR 0007; operator, migration, and rollback documentation; and adversarial
  coverage for staleness, drift, malformed receipts, path escape, symlinks,
  invalid applicability, waiver abuse, and release integration.
- Added `web-launch-assurance`, `email-deliverability`,
  `product-observability`, and `privacy-legal-evidence` capability packs inside
  the existing five workflows.

### Changed

- Production release readiness now requires a current passing launch receipt
  in addition to QA, security, approval, rollback, and monitoring evidence.
- Public-web, commercial, payment, and regulated-data launch profiles now
  require a complete repository-wide release-profile audit by default.
- Upgraded all five existing commands without adding a sixth command. Launch
  evidence routes through current Lead, Security, QA, DevOps, Product,
  Reviewer, Architect, Documentation, and accountable human owners.
- Expanded deterministic packaging to mirror the launch registry and schemas,
  and expanded the canonical MCP inventory from 50 to 53 tools.

### Security

- Blocker launch controls are unwaivable. Eligible required waivers require an
  owner, reason, external reference, bounded expiry, compensating control, and
  residual risk, and policy can disable them.
- Launch receipts bind Git HEAD, workspace fingerprint, base, policy, tool,
  catalog, selection, surfaces, target, environment, server session, artifact
  hashes, verifier attestations, and freshness. Raw artifact content is never
  returned.
- Launch readiness remains evidence only and always reports
  `executionAuthorized=false`. The v0.7 exact one-action external authority
  boundary is unchanged, including for live payment and production checks.

### Attribution

- Adapted the concepts in Nico Burkart's reviewed 37-point pre-launch checklist
  into conditional, paraphrased JStack engineering controls. Vendor-specific
  recommendations and legal judgments remain advisory, conditional, or
  human-owned as documented in `docs/launch-assurance.md`.

## 0.7.0 - 2026-07-21

### Added

- Added a mandatory local-only default and exact authorization protocol for
  eleven separate repository, Git, release, deployment, and production actions.
- Added `jstack_external_action_challenge`,
  `jstack_external_action_authorize`, and
  `jstack_external_action_consume`. One independently signed challenge binds
  exactly one action to provider, owner, repository, visibility, remote URL,
  branch, tag, full commit, environment, current Git/workspace/policy state,
  remote snapshot, JStack version, MCP session, identity role, and expiry.
- Added destructive one-time consumption after a fresh exact provider
  observation and a single-operation permit valid for at most 60 seconds.
- Added a separate external-action identity template and operator signer that
  requires the full displayed challenge digest, plus versioned intent and
  consumption schemas.
- Added protocol, migration/rollback, security, architecture, and ADR 0006
  documentation with adversarial tests for replay, action escalation,
  ambiguity, Git/remote/provider/visibility drift, artifact-only use, policy
  weakening, and signer confirmation.

### Changed

- Upgraded all five existing commands without adding a sixth command. Broad
  task verbs, staffing/phase/remediation approval, audit results, readiness,
  specialist handoff, and loop/program completion are explicitly non-authority.
- Strengthened loop and program default blocked actions so every protected
  action remains outside their completion and human-gate authority.
- Changed release readiness to report `executionAuthorized=false` even when
  evidence is ready; caller booleans and approval references remain readiness
  inputs only.
- Made branch pushes and tag pushes distinct exact `push` intents. A
  branch-only push requires `tag=not-applicable` and the named local branch
  tip to equal `exactCommit`; a tag-only push requires the exact local tag to
  peel to `exactCommit`.
- Extended deterministic packaging to mirror the authorization module, signer,
  schemas, identity template, and updated command contracts.

### Security

- Missing fields, placeholders, wildcards, detached HEAD, abbreviated commits,
  unsafe refs, embedded remote credentials, ambiguous remotes, unsigned or
  non-canonical attestations, role mismatch, expiry, replay, retry, subject
  drift, remote drift, provider/visibility mismatch, and action substitution
  fail closed.
- The MCP still performs no protected action and exposes no arbitrary executor.
  Host/tool restrictions and provider protections remain necessary against
  direct non-JStack bypass or same-account compromise.

## 0.6.0 - 2026-07-21

### Added

- Added a strict, versioned 14-pack specialist capability registry that routes
  task-specific methods, required evidence, stop conditions, audit domains, and
  loop controls to JStack's existing core roles without adding a sixth command.
- Added `jstack_capability_catalog`, `jstack_specialist_result`, and
  `jstack_specialist_handoff_check` with published catalog, result, and
  telemetry schemas.
- Added schema-validated specialist results, privacy-minimized execution
  telemetry, per-role session receipts, complete-team handoff receipts,
  contradiction reconciliation, and change-ownership enforcement.
- Added adversarial coverage for catalog corruption, unauthorized explicit
  capabilities, permission elevation, missing evidence, raw-content telemetry,
  receipt tampering/staleness, missing roles, contradictions, audit routing,
  and loop handoff gates.

### Changed

- Upgraded `/j-stack-dev`, `/jstack-subagents`, and `/jstack-full-team` to use
  deterministic role-to-capability assignments while preserving their existing
  staffing and permission boundaries.
- Upgraded `/jstack-audit` so bounded specialist routing can strengthen—but
  never remove—required audit domains, with catalog and selection binding in
  its signed session and final receipt.
- Upgraded `/jstack-loop` to persist capability contracts through readiness,
  start, revision, checkpoint, and completion. Multi-agent loop evidence now
  requires a current specialist handoff receipt.
- Extended deterministic packaging so the canonical capability registry and
  schemas are mirrored and inventory-checked in the umbrella plugin.

### Security

- Telemetry exposes no raw prompt, message, tool-argument, model-output, or log
  fields; recognized raw-content keys and secret-like values are rejected.
  Input and output digests are derived by the server.
- Capability entries must inherit role permissions; unknown fields, roles,
  unsafe source paths, invalid patterns, duplicate IDs, routing drift, and
  permission expansion fail closed.

### Attribution

- Adapted selected engineering, testing, security, and handoff guidance from
  `msitarzewski/agency-agents` at commit
  `459dce837db3bdfdc4763d3fefd1fd854e73c8f1` under MIT. Exact source paths and
  the upstream license notice are in `THIRD_PARTY_NOTICES.md`; no upstream
  installer, agent roster, runtime, or permission model was imported.

## 0.5.0 - 2026-07-16

- Added a phase-count-agnostic Program -> Phase orchestration protocol above
  bounded JStack child loops for long, heterogeneous, or dependency-driven
  projects.
- Added 14 program MCP tools for exact readiness, durable start/status,
  conservative DAG scheduling, child binding/completion, human and external
  gates, pause/resume/revision/cancellation, and finalization.
- Added exact child-contract matching, durable loop completion attestations,
  declared-output hashing, transitive invalidation, baseline/policy/tool
  revalidation, and final release-audit/security/integrated-review floors.
- Added signed-local human identities with role and quorum checks, exact
  contract-bound approval challenges, an external operator signer, and
  freshness-aware external artifact evidence.
- Added active-work clocks that exclude human, external, and manual waits;
  approval-paused child loops release and explicitly reacquire write leases.
- Added transactional idempotency keys for every state-changing program call,
  hash-chained program events, versioned contracts, pending-write recovery, and
  private state outside the repository.
- Added active-budget freezing, orphaned-start reference recovery, history-wide
  start idempotency, scheduler-enforced binding, inherited blocked actions,
  revision-safe gate clearing, descriptor-safe evidence hashing, and repeatable
  completion revalidation.
- Published JSON Schemas for contracts, status, gates, and evidence plus
  enterprise policy/identity templates, ADR 0004, operator documentation, and
  a 0.5 migration/rollback guide.
- Updated `/jstack-loop` to choose one bounded loop or a project-derived
  multi-phase program and compose each phase with explicitly approved
  single-lead, specialist-team, or full-team delivery.
- Added variable-size, end-to-end child proof, human gate, external evidence,
  idempotency, active-time, lease, tamper, and program finalization coverage.

## 0.4.1 - 2026-07-15

- Added mandatory semantic goal readiness before loop start and material
  contract revision, including structured domain context, source attribution,
  assumptions, unresolved questions, and explicit inference tracking.
- Added adaptive intake with the complete gap set and at most three targeted
  questions per round, including niche requirements for product, security,
  financial/data, production, research, and unknown domains.
- Added exact-digest confirmation for ambiguous, inferred, assumption-bearing,
  sensitive-domain, medium-or-higher-risk, and L3 contracts.
- Added short-lived session-local readiness receipts bound to the exact semantic
  contract, Git fingerprint, policy, tool version, loop ID, and prior revision.
- Persisted additive goal context/readiness metadata while retaining read
  compatibility with 0.4.0 loop state and approval-only resume revisions.
- Added adversarial coverage for incomplete intake, stale confirmation,
  contract-mismatched receipts, material revisions, sensitive-domain questions,
  and unsafe repository context sources.

## 0.4.0 - 2026-07-15

- Added `/jstack-loop` as a fifth workflow that composes Codex Goal mode with
  an explicitly selected JStack single-lead, specialist-team, or full-team
  execution mode.
- Added six fail-closed loop MCP tools for start, status, checkpoint, contract
  revision, stop, and evidence-bound finalization.
- Added versioned Git-bound contracts, clean-start write controls, linked
  worktree attestation for L3, one active write lease, private atomic state,
  validated revision history, snapshot-bound SHA-256 hash-chained events, and
  interruption recovery.
- Added current QA, security, audit, deterministic review, artifact, and named
  approval criteria plus path, policy, protected-file, change-count, and
  no-op completion controls.
- Added iteration, elapsed-time, no-progress, repeated-failure, and oscillation
  circuit breakers without weakening Codex Goal complete/blocked semantics.
- Added the dedicated and umbrella loop skill/plugin surfaces, legacy installer
  support, architecture and operator documentation, and generated-artifact
  parity.
- Added a ten-stage loop-engineering mastery curriculum and atomic mastery
  profile v1/v2 to v3 migration while preserving engineering and audit state.
- Added signed Stage 9 loop capstone attestations, exact baseline ancestry,
  segment-aware scope globs, circuit-breaker resume approvals, hidden-index and
  unsafe Git path rejection, and policy/tool-version drift gates.
- Adapted loop/goal separation and staged-learning concepts from the Cobus
  Greyling reference repositories without adding an upstream runtime or copied
  source dependency.

## 0.3.1 - 2026-07-13

- Kept the umbrella plugin's default prompts within Codex's three-prompt
  manifest limit while retaining all four workflows in its description and
  dedicated plugin surfaces.

## 0.3.0 - 2026-07-13

- Added the read-only `/jstack-audit` workflow with quick, standard, deep, and
  release profiles.
- Added deterministic `jstack_audit` and `jstack_audit_finalize` MCP contracts,
  versioned findings/results, coverage matrices, Markdown summaries, and SARIF
  2.1.0 output with stable fingerprints.
- Added a versioned control catalogue, repository/path/limit/redaction
  hardening, curated analyzer discovery, and explicit suppression validation.
- Added session-local audit receipts while preserving the existing secret-scan
  receipt and release-readiness behavior; the audit release gate is opt-in.
- Added a separate ten-stage audit mastery curriculum and atomic profile v1 to
  v2 migration with engineering remaining the default track.
- Added umbrella, dedicated plugin, legacy installer, compatibility,
  adversarial, and seeded audit fixture coverage.
- Bound suppression expiry to server time and release-time revalidation, and
  made release receipts require complete repository and release-range scope.
- Made Quick execution impossible, failed adapters incomplete, Node launchers
  discovery-only until toolchain identity can be attested, and requested output
  formats transport-bounded.
- Made Stage 9 blindness depend on runtime-keyed independent assessor
  attestations for two distinct challenge subjects; the bundled answer key is
  explicitly a transparent practice benchmark.
- Added transaction-wide installer rollback and exact generated-tree inventory
  checks that reject stale packaged files without rewriting unrelated files.

## 0.2.1 - 2026-07-10

- Added `jstack_runtime_status` so clients can prove MCP mount state without a
  Git repository.
- Added explicit `git` and `artifact-only` project bindings for detection and
  planning.
- Added artifact-only evidence requirements for hashes, tests, backups,
  immutable runtime identity, rollback, monitoring, and smoke checks.
- Kept policy, preflight, review, QA, security receipts, context receipts,
  mastery records, quant review, and release readiness fail-closed on non-Git
  directories.
- Updated all command surfaces to distinguish MCP availability from Git project
  eligibility and stop misreporting Git rejection as an attachment failure.

## 0.2.0 - 2026-07-10

- Replaced incompatible Content-Length framing with MCP JSONL stdio transport.
- Made command mode authoritative for single-lead, smart-subagents, and
  full-team workflows.
- Added non-overridable policy floors and complete committed/worktree change
  evidence.
- Added explicit-trust QA execution with scrubbed environment, isolated home,
  mutation detection, and signed evidence receipts.
- Bound release readiness to an explicit base, clean commit, policy digest,
  exact command receipts, complete security scan, approval reference, rollback,
  and monitoring.
- Hardened secret scanning for dotfiles, symlinks, truncation, source previews,
  and secrets added then deleted inside a release range.
- Added dispatch role, packet, permission, containment, and semantic overlap
  validation.
- Added a ten-stage evidence-backed mastery curriculum with local progression
  records and assistance caps.
- Added deterministic artifact synchronization, portable plugin launch,
  staged installers, adversarial tests, and cross-platform CI.
