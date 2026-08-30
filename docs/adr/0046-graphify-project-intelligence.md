# ADR 0046: Graphify-Backed Project Intelligence

- Status: Accepted
- Decision date: 2026-08-29
- Applies to: JStack Dev, Subagents, Full Team, Audit, Loop, Program, and release readiness

## Context

Large codebases impose a context-selection problem before implementation even
begins. Flat file search and broad source loading can miss dependency paths,
consume unnecessary context, and make impact claims hard to bind to the exact
candidate. A graph can improve navigation, but an inferred graph is not a
source of implementation or release authority and a hosted semantic service
would introduce privacy, credential, availability, and provenance concerns.

## Decision

JStack will use a pinned Graphify local-AST runtime as a managed provider
inside a new native Project Intelligence protocol. The protocol exposes five
canonical-only MCP operations for index, bounded query, impact, refresh, and
finalization. It adds no slash command, role, standalone skill, permission, or
parallel authority plane.

Material, risk-sensitive, cross-module, team, audit, loop, program, and release
work on supported existing source requires the provider and fails closed.
Trivial, non-code, greenfield, and unsupported cases use explicit documented
skip or deferral states.

Every immutable graph snapshot is private and bound to the exact repository,
Git commit and tree, dirty fingerprint, JStack policy, provider catalog, graph
digest, and manifest digest. A release finalization additionally binds the
original change-base commit and the exact derived changed-path set.

Only source-anchored `EXTRACTED` relationships qualify as strong graph
evidence. Inferred, ambiguous, and unanchored relationships are advisory and
must be checked in source. Finalization always requires direct source reads,
tests, and independent review.

The installer provisions the pinned distribution only after explicit opt-in,
in an isolated versioned runtime outside Codex skills and project repositories.
Runtime invocation uses local AST and static HTML commands only. JStack does
not activate hosted services, semantic providers, listeners, HTTP MCP, hooks,
repository instruction edits, or Graphify's own assistant installer.

## Enforcement Boundary

The MCP can reject missing providers, stale or tampered receipts, graph/hash
drift, unsafe paths, oversized work, missing direct evidence, and release
candidate mismatch. It cannot prove that an AST extractor is semantically
complete, that a reviewer is honest, or that runtime behavior follows every
static relationship. It also cannot intercept work performed outside the
JStack workflow.

The generated HTML is an interactive navigation artifact only. It conveys no
permission or correctness claim and remains private under `~/.jstack`.

## Rejected Alternatives

- A separate Graphify slash command or skill: rejected because project
  understanding belongs inside every applicable JStack workflow.
- On-demand use only: rejected for material work because optional invocation
  would leave the largest and riskiest changes least consistently covered.
- A hosted or semantic provider by default: rejected for privacy, credential,
  reproducibility, and dependency reasons.
- Git hooks or repository instruction injection: rejected because installation
  must not mutate project behavior or silently govern non-JStack work.
- Treating all graph edges as evidence: rejected because confidence labels and
  source anchors have materially different epistemic strength.
- Replacing source reads or tests with graph traversal: rejected because a
  static graph is a context selector, not a correctness oracle.

## Consequences

Applicable JStack work incurs local indexing and explicit refresh cost, plus a
larger opt-in runtime dependency. In return, planning, teams, audits, loops,
and release readiness share one bounded, candidate-bound project model and one
visible graph artifact. Users without the runtime can still use JStack for
genuinely non-applicable work, but mandatory work stops with an actionable
installation message.

The pinned top-level wheel is hash verified. Cross-platform transitive binary
dependencies remain resolved at provisioning time rather than by a complete
hash lock, so this ADR records that residual supply-chain risk for future
hardening.
