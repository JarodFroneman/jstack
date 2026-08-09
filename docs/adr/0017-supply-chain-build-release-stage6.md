# ADR 0017: Exact Supply-Chain And Build Evidence At Audit Stage 6

- Status: Accepted
- Date: 2026-08-09
- Target release: 0.10.0-alpha.7

## Context

Audit mastery Stages 0 through 5 established safe operation, repository
mapping, correctness, threat modelling, architecture, and signed performance
evidence. Stage 6 must teach dependency, CI, build, provenance, and generated-
artifact judgment without allowing a model-authored inventory, an unexecuted
scanner claim, or a mutable workflow reference to pass as verified evidence.

No language-independent static parser can prove every transitive dependency or
reproduce every build. Advisory scanners are also limited by installed tools
and available local advisory data. The deterministic boundary therefore needs
to distinguish what JStack can recompute from immutable Git objects, what a
separately approved scanner attests, and what remains an explicit finding or
limitation.

## Decision

1. Ship closed `jstack.audit.dependency-inventory.v1` and
   `jstack.audit.supply-chain-report.v1` contracts plus one non-empty,
   hash-bound `build-trace.md`.
2. Permit only `.jstack-training/dependency-inventory.json`,
   `.jstack-training/build-trace.md`, and
   `.jstack-training/supply-chain-report.json` to be dirty during an attempt.
3. Enumerate tracked manifests, lockfiles, dependency policies, build
   configurations, GitHub workflows, provenance files, and conventional
   generated artifacts from the exact baseline and candidate Git trees.
   Recompute every represented blob's SHA-256 and byte size and reject any
   omitted or invented input.
4. Support static classification across JavaScript/TypeScript, Python, Rust,
   Go, JVM, Ruby, PHP, .NET, C/C++, Bazel, Swift, Dart, Elixir, containers,
   Haskell, R, GitHub Actions, and generic build artifacts. Classification proves bounded
   tracked-input enumeration, not semantic dependency completeness.
5. Parse every closed-form GitHub Actions `uses:` reference and top-level
   `permissions:` declaration from immutable blobs. Reject dynamic or
   unparseable action references. Mutable action tags, implicit or unsupported
   permissions, and unbounded writes require explicit verified findings.
6. Require a source/configuration/dependency-to-artifact graph, explicit
   material provenance for every candidate artifact, and representation of
   every conventionally discovered generated artifact. Recompute exact-copy
   status when source paths are declared; missing provenance and drift remain
   findings rather than silently becoming clean results.
7. Extend the final audit receipt with a bounded sanitized adapter-result
   summary. Stage 6 requires a current, complete, same-session receipt whose
   required domains include `supply-chain` and whose represented curated
   `dependency-analysis` adapters passed without repository mutation.
   Scanner stdout, stderr, source previews, and secrets are never placed in the
   receipt or mastery record.
   Provide `osv-scanner-offline` as the cross-ecosystem option only when its
   executable and a caller-provisioned external local database directory are
   available. Enforce OSV offline mode and bind the resolved executable and
   database path into the exact subject; do not download advisory data during
   evaluation or adapter execution.
8. Require a current passing receipt for every QA command discovered at the
   exact candidate state. Dependency scanning never substitutes for
   correctness testing.
9. Keep `a6-supply-chain` read-only: baseline equals candidate, findings remain
   open, and remediations remain proposed. Keep mutation outside Audit. For
   `a6-hardening`, accept only a separately authorized committed candidate with
   a strict ancestor baseline, exact Git-diff reconciliation, one resolved
   finding, one implemented-and-verified control, and matching QA evidence.
10. Return only subject metadata, counts, failure codes, and an evaluation
    digest. Do not echo source, findings, build narratives, scanner output, or
    dependency content from deterministic evaluation.
11. Require three independent deterministic passes across at least two
    commits, every score at least 80, a mean of at least 85, and both named
    drills before advancement.

## Consequences

Stage 6 makes omitted lockfiles, mutable Actions references, implicit token
permissions, hidden generated copies, unverifiable provenance, fabricated
scanner claims, stale receipts, and mismatched hardening diffs machine-
detectable. It remains useful across major implementation languages because
the core proof is Git-object and workflow evidence, while ecosystem scanners
remain curated adapters.

A pass does not prove a complete transitive dependency graph, a complete or
current advisory database, reproducible builds, artifact authenticity outside
the cited evidence, vulnerability absence, or release readiness. Curated local
scanner execution is not an OS or network sandbox. Audit cannot update a
dependency, edit CI, commit, publish, release, deploy, or access production;
those actions remain separately authorized development or release work.
