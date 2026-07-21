# Audit Methodology

## Contents

1. Profiles
2. Coverage
3. Evidence sequence
4. Team modes
5. Reporting

## Profiles

- `quick`: changed files and release range, diff hygiene, secret scan, and
  obvious correctness/security/test regressions. Never claim a clean whole
  repository.
- `standard`: changed modules, direct callers/dependencies, associated tests,
  interfaces, configurations, trust boundaries, and every applicable domain.
- `deep`: bounded whole-repository review across all domains, architecture and
  trust maps, challenge pass, and approved analyser evidence where required.
- `release`: exact distinct base, complete required domains, current QA and
  existing security receipts, no truncation/staleness, rollback context, and a
  defensible go/no-go decision.

The profile fixes its evidence requirements before findings are reviewed. Do
not downgrade a missing check after seeing the result.

`--focus` prioritizes semantic review effort and specialist selection; it does
not remove any domain or evidence requirement fixed by the selected profile.
`jstack_audit` routes the focus through the versioned capability registry. The
selected packs may add required audit domains and evidence methods. The audit
session and final receipt bind the catalog and selection digests, so a changed
catalog or focus cannot be silently substituted during finalization.

## Coverage

Classify each required domain as `complete`, `incomplete`, `unsupported`, or
`not-applicable`. A `not-applicable` claim needs a reason and evidence. Unknown,
unreadable, capped, stale, unsupported, or required-adapter gaps make the audit
`incomplete`.

Required domains are correctness, security, maintainability, architecture,
performance, supply chain, testability, operations, data integrity, and API
compatibility. Use the versioned MCP control catalogue as the source of truth.

## Evidence Sequence

1. Bind root, scope, HEAD, base, workspace, policy, controls, adapters, and
   scope-manifest digest.
2. Map languages, entry points, dependencies, tests, configuration, generated
   copies, data flows, and trust boundaries.
3. Gather deterministic review, change, and existing secret-scan evidence.
4. Generate candidates with exact locations and violated contracts.
5. Challenge candidates against reachability, guards, tests, callers, and
   controls.
6. Reproduce safely or classify the strongest support actually available.
7. Deduplicate, validate suppressions, calculate coverage, and finalize.
8. Produce concise Markdown, structured JSON, and SARIF when requested.

Never execute repository code merely to improve confidence. A missing approved
verification step is a visible coverage gap.

## Team Modes

`single-lead` is the default. `smart-subagents` selects at most three
read-only specialists by focus. `full-team` uses four waves:

1. Discovery and system mapping.
2. Domain review.
3. Challenge and verification.
4. Lead synthesis and go/no-go.

Every specialist returns scope, evidence, severity-ordered findings, blockers,
residual risk, and recommended action. Evidence wins conflicts.
When platform specialists are used, route the exact core-role capability IDs,
validate `jstack.specialist.result.v1` plus metadata-only telemetry for each
role, and obtain a clean specialist handoff receipt before synthesis. These
receipts do not replace the audit finding/result schemas or audit receipt.

## Reporting

Lead with status and coverage. Then list verified findings by severity, each
with location, evidence state, failure path, impact, remediation, verification,
and residual risk. Follow with suppressed findings, incomplete areas, explicit
go/no-go, and limitations. Write `None` for an empty material section.
