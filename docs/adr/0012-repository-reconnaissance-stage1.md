# ADR 0012: Deterministic Repository Reconnaissance At Audit Stage 1

- Status: accepted
- Date: 2026-08-02
- Target release: 0.10.0-alpha.2

## Context

Later security analysis and remediation cannot be trustworthy when the agent
does not know the real entry points, dependency and build paths, data flows,
trust boundaries, test surfaces, generated copies, or authoritative source.
Free-form prose maps are easy to fabricate, become stale silently, and cannot
be consumed as deterministic advancement evidence.

Stage 0 established the operator authority boundary. Phase 1 must establish a
repository-comprehension boundary without prematurely adding scanners,
execution, exploit verification, patch generation, CI pull requests, or
production authority.

## Decision

1. Keep the existing five commands, 50 canonical MCP tools, Audit read-only
   boundary, and mastery profile v3.
2. Add a closed `jstack.audit.repository-map.v1` schema as the machine-readable
   contract for Stage 1 `coverage-matrix.json`.
3. Bind the mapped source to exact Git HEAD and tree. Record the complete
   project fingerprint separately in the attempt, because embedding a
   fingerprint that includes the map itself would create an impossible
   self-reference.
4. Require exactly eight surfaces: architecture, entry points, data flows,
   trust boundaries, tests, dependencies, build/release, and generated
   artifacts. Evidence-backed `not-applicable` is valid; `unsupported`, gaps,
   or incomplete coverage cannot pass.
5. Require every material surface, node, flow, trust boundary, and generated
   artifact to reference bounded evidence IDs. Each evidence record must cite
   a tracked regular file, valid line range, and current SHA-256.
6. Validate identifier uniqueness, graph endpoints, boundary references,
   evidence use, generated source provenance and drift risk, exact static
   collection boundaries, and exact limitations.
7. Permit only the three declared Stage 1 artifacts under
   `.jstack-training/`; any source/configuration/Git change hard-blocks the
   attempt.
8. Return only source-subject metadata, counts, deterministic failure codes,
   and an evaluation digest. Never echo raw map or repository content.
9. Require two consecutive independent attempts scoring at least 80 and
   deterministically passing this contract.
10. Ship this bounded phase as `v0.10.0-alpha.2`. Do not represent it as
    scanning, vulnerability absence, zero-day detection, exploitation,
    remediation, release readiness, deployment safety, or production access.

## Consequences

Stage 1 produces a reproducible structural foundation that later phases can
consume and challenge. Stale or unsupported maps fail visibly, generated-copy
drift is explicit, and prose confidence cannot substitute for cited source.

The evaluator proves contract compliance, not semantic truth. A human or model
can still misunderstand source while producing syntactically valid citations.
Later correctness, threat-model, scanner, adversarial-verification, patch, CI,
and human-review stages remain necessary and separately authorized.
