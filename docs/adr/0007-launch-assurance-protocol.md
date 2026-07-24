# ADR 0007: Applicability-Aware Launch Assurance

> Update: external-action authorization details in this historical decision
> were superseded by [ADR 0008](0008-host-native-action-safety.md) in v0.8.2.

- Status: accepted
- Date: 2026-07-22
- Decision owners: JStack maintainers

## Context

JStack 0.7 could bind QA, secret/security scans, repository audits, rollback,
monitoring, and human release references to an exact Git subject. It did not
model whether a product sends email, exposes a browser surface, takes payments,
uses tracking, expects search indexing, or handles regulated data. Consequently,
important pre-launch checks existed only in prose or project-specific prompts,
and `requiredChecks` names were not a typed product-surface gate.

A flat universal checklist would create false blockers for inapplicable
projects. A prompt-only checklist would remain easy to omit, relabel, or satisfy
with stale narrative claims. A new slash command would fragment the existing
five workflows and create another authority surface.

## Decision

Add a versioned 37-control catalog and three read-only MCP tools inside the
existing workflows:

1. `jstack_launch_assess` creates an explicit surface profile and signed,
   commit-bound selection contract.
2. `jstack_launch_evidence_register` hashes one bounded artifact and records a
   typed, expiring verifier attestation for one selected control.
3. `jstack_launch_finalize` resolves the selection fail-closed and issues a
   release-consumable receipt.

Production release readiness requires the final receipt. Public-web,
commercial, payment, and regulated-data profiles additionally require a
repository-wide release-profile audit by default.

The catalog separates source priority from JStack gate level. Blockers are
unwaivable. Eligible required waivers are owned, reasoned, referenced,
expiring, compensated, and explicit about residual risk. `not-applicable` is
permitted only where catalog metadata allows it and still needs evidence.

All receipts bind the current Git subject, policy, tool version, catalog,
selection, environment, target, and server session. Evidence artifacts are
content-free in output and limited to the project or `~/.jstack/evidence`.

## Authority boundary

Launch readiness is evidence, not authority. The tools perform no network,
Git, provider, release, deployment, payment, or production action. The exact
one-time external-action protocol from ADR 0006 remains mandatory and
unchanged. Live payment evidence never broadens production-mutation authority.

## Consequences

- Production release-readiness callers must migrate to supply a passing launch
  receipt.
- Applicability becomes explicit and reviewable instead of inferred.
- Email, browser, search, analytics, payment, tracking, and legal controls no
  longer burden projects that do not declare those surfaces.
- A named verifier remains accountable for semantic truth; JStack proves
  binding and freshness, not the correctness of an external report or legal
  decision.
- Catalog or policy changes intentionally invalidate prior launch receipts.
- The five workflows gain four routed capability packs without adding a role,
  command, write permission, or publication authority.

## Rejected alternatives

- A sixth launch slash command: rejected because launch assurance belongs in
  development, team, audit, loop, and release workflows.
- A universal 37-item gate: rejected because it would create false failures and
  encourage dishonest not-applicable claims.
- Free-text evidence fields in release readiness: rejected because they are
  not typed, independently fresh, or bound to individual controls.
- Automatic surface inference: rejected as the final authority because code
  cannot reliably determine legal, merchant, tracking, mailbox, and production
  facts.
