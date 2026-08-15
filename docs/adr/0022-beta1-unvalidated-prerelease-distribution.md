# ADR 0022: Beta.1 Unvalidated Prerelease Distribution

- Status: Accepted; unvalidated prerelease distribution approved
- Date: 2026-08-15
- Target release: 0.10.0-beta.1
- Amends: [ADR 0021](0021-beta1-codex-proof-study.md) distribution timing only

## Context

The code-only `0.10.0-beta.1` candidate passed its deterministic product,
compatibility, security, and audit gates. This amendment changes the release
commit, so publication remains conditional on rerunning those gates against
the exact final commit; no earlier receipt is reused. The Apple-container study
and its independent human-review panel remain unavailable on the desired
release timeline. The project owner explicitly directed JStack to distribute
Beta.1 without substituting synthetic or model-authored reviews for that
missing evidence.

ADR 0021 correctly prevents an incomplete study from becoming a validation or
uplift claim. It also coupled that claim gate to every prerelease tag,
publication, and installation. This amendment separates those two decisions
without changing the study protocol.

## Decision

1. JStack may publish the exact `v0.10.0-beta.1` commit as a GitHub
   **prerelease** and install that exact released payload in Codex before the
   216-run study and 432 primary reviews exist.
2. Every release-facing surface must call this distribution **unvalidated**.
   It is not a stable release, production-readiness certification, completed
   study, human-review result, or measured JStack-uplift result.
3. The public Proof Plane manifest remains `development-only`, retains an
   empty execution plan, and keeps every result/quality claim disabled.
4. No fixture, AI-authored review, self-attestation, partial denominator, or
   release receipt may stand in for the deferred study or human evidence.
5. ADR 0021 remains the complete validation contract. Any later Beta.1 study
   must bind its installable product, MCP, plugin, and 52-tool bytes to the
   exact published release tag. Study-only registrations and eval artifacts
   may be added on the separately required `proof-beta1-registration-*` tag;
   any change to installable product bytes requires a new prerelease identity
   and new evidence.
6. Normal product QA, security scanning, named human security review or review
   reference, explicit release-owner approval, deterministic review, release
   readiness, provider permissions, rollback preparation, and installed-byte
   verification remain mandatory. This amendment defers only the Proof Plane's
   image/run evidence and 432 primary human-review assignments as prerequisites
   to prerelease distribution.
7. GitHub must mark the release as a prerelease. Release notes, the changelog,
   migration guide, and README must prominently retain the missing-evidence
   boundary. The release must not be promoted to a stable/latest production
   release without a new evidence-backed decision.
8. Global installation must use the exact tagged release, preserve the prior
   installation as a recoverable rollback unit, retain the five-command and
   52-tool layout, and verify MCP/plugin version and source-to-install parity.

## Consequences

- Users can exercise the completed Beta.1 product code while the independent
  study is scheduled separately.
- Public availability proves distribution and installability only. It does not
  improve the evidence status of the Proof Plane or support performance,
  quality, security-superiority, or human-review claims.
- The 18 image qualifications, 216 attempts, 432 primary reviews,
  adjudications, scoring, and independent evidence verification remain
  visibly pending.
- A rollback restores the last released Alpha.10 installation without
  rewriting or reinterpreting private Beta.1 study state.

## Rejected Alternatives

- Silently deleting ADR 0021's gates: rejected because it would erase the
  decision history and make the release boundary ambiguous.
- Calling deterministic tests or AI review “human validation”: rejected
  because those evidence classes are not interchangeable.
- Publishing Beta.1 as stable/latest: rejected because the defining external
  validation has not run.
- Fabricating a partial score or zero-valued result: rejected because absence
  of evidence is not a measured outcome.
