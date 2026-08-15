# ADR 0021: Beta.1 Codex Proof Study

- Status: Accepted validation contract; prerelease distribution timing amended
  by [ADR 0022](0022-beta1-unvalidated-prerelease-distribution.md)
- Date: 2026-08-12
- Target release: 0.10.0-beta.1

## Context

Alpha.10 made benchmark contracts and scoring arithmetic testable, but its
mock fixture cannot measure repository-level engineering quality. Beta.1 must
produce real evidence without adding a sixth JStack command, changing the 52
tool product surface, placing model clients in core, or treating an incomplete
study as a result.

## Decision

1. Keep the Proof Plane under `evals/` and `tools/proof_plane/` as uninstalled
   maintainer infrastructure. The installed MCP remains standard-library-only
   and keeps exactly five workflows and 52 canonical tools.
2. Use exactly 18 tasks: seeded defect, historical replay, and clean control
   for each of TypeScript/web, Python API, Java/C# service, C/C++ system,
   data/database, and legacy-repository families.
3. Preregister exactly 216 primary attempts: 18 tasks, controlled and
   operational modes, plain and JStack conditions, and three repetitions.
   Every planned cell receives exactly one scored invocation. Failed, blocked,
   and timed-out cells remain in the denominator; diagnostic retries never
   replace them.
4. Measure two distinct estimands. Controlled mode gives both conditions the
   identical four-tool Proof broker and therefore measures the frozen JStack
   workflow protocol. Operational mode gives the JStack condition that broker
   plus the exact frozen 52-tool MCP and reports it as a separate product-
   surface comparison with condition-specific tool bindings.
5. Bind the complete plan before the first attempt to an annotated published
   Git tag, exact task/source/brief/holdout/image/tool digests, Codex CLI and
   observable model configuration, exact Codex executable digest and package
   provenance, qualification command/receipt-set digests, numeric budgets,
   tool surfaces, randomized balanced schedule, and evidence bindings. A
   deterministic harness lock covers every Proof Plane module, eval validator,
   scorer, schema, and protocol; the lock excludes only itself and its raw
   digest is registered. A plan derived from produced runs is invalid.
6. Execute project code only in a digest-pinned, image-qualified Apple
   container VM with an inner Bubblewrap network/process namespace, read-only
   root, non-root identity, dropped capabilities, bounded resources, no
   secrets, no published ports or forwarded sockets, and only the candidate
   workspace writable. The exact image and invocation must pass the frozen
   isolation canary before any model starts.
7. Keep every hidden test and answer key outside every model VM. No grader may
   resolve or mount holdout material until all 216 model attempts have a
   write-once terminal receipt. Grading reconstructs the source and patch in a
   new, separately identified VM and returns bounded structured evidence only.
8. Give each candidate to exactly two genuine independent human reviewers in
   an opaque packet. Primary reviewer sets for paired plain/JStack candidates
   are disjoint. Any disposition or metric-count disagreement requires a human
   adjudicator who was not a primary reviewer for either candidate in that
   matched pair. Canonical primary submissions and adjudications are verified
   with OpenSSH signatures against a preregistered public-key roster; AI agents
   do not count as reviewers. Whole-study assignment and finalization receipts
   bind this pair-wide check.
9. Bind every run to its start and terminal receipts, append-only tool ledger,
   externally anchored ledger state, model result/transcript/patch digests,
   fresh grader receipt/result, opaque packet, signed reviews, finalized public
   review, and closed canonical attestation. Attestations alone cannot unlock
   scoring: the locked verifier must re-hash all 216 private chains, verify all
   432 primary signatures and every adjudication signature, and issue a
   canonical whole-study verification receipt bound to the registration,
   schedule, harness lock, roster, expected runs, and attestation set. A
   separately preregistered evidence-verifier key must sign that receipt in a
   fixed OpenSSH namespace; a self-digest or unsigned receipt is insufficient.
10. Store source caches, holdouts, raw JSONL, command output, patches, reviewer
    assignments, and identities only in a permission-restricted, gitignored
    `.jstack-evals/` tree. Publish only minimized contracts, counts, digests,
    honest limitations, and aggregate results.
11. Treat model USD cost, local compute USD, provider queue time, immutable
    backend snapshot, post-release incidents, and rollbacks as unavailable
    unless separately observed. Required numeric v1 placeholders are
    suppressed from the Beta.1 report and never interpreted as measured zero.
12. The studied candidate bytes may identify themselves as
    `0.10.0-beta.1` so registration, MCP initialization, packages, and the
    eventual evidence all bind one exact version identity. ADR 0022 permits
    the exact bytes to be tagged, published as an explicitly unvalidated
    prerelease, and installed before the study. Do not describe the candidate
    as validated, promote it as a stable production release, publish study
    results, or claim uplift until all 18 images qualify, all 216 attempts
    terminate, all 432 primary human reviews and any adjudications verify, the
    exact scorer succeeds, and the full validation gates pass.

## Consequences

- Beta.1 can eventually report a reproducible, configuration-specific Codex
  study with failures retained and review evidence independently attributable.
- The study cannot establish universal superiority, vulnerability absence,
  universal zero-day detection, production readiness, or results for Claude or
  other untested hosts.
- Installing a container runtime and recruiting the human review panel are
  external validation prerequisites. Missing either blocks validation and
  every study/result/uplift claim; ADR 0022 permits only an explicitly
  unvalidated prerelease distribution and never synthetic evidence.
- Additional installer lifecycle hardening, portable evidence bridges, signed
  distribution artifacts, SBOM/provenance, and host-parity work remain Beta.2
  scope. ADR 0022 authorizes Beta.1's existing exact-tag source installation
  and dedicated-plugin Layout B with rollback and byte-parity verification.

## Rejected Alternatives

- Host execution of repository commands: rejected because JStack QA is not an
  operating-system sandbox and the benchmark intentionally exercises
  untrusted candidate code.
- macOS `sandbox-exec` as a container label: rejected because it is deprecated
  and does not satisfy the registered container/microVM contract.
- Grading each run immediately: rejected because it can leak withheld answers
  into paired conditions and later repetitions.
- Self-asserted or AI-generated reviews: rejected because they do not satisfy
  the independent human-review protocol.
- Publishing a partial denominator or presenting a protocol-only Beta.1 as a
  validated result: rejected because the selected validation gate is the full
  216-run study. ADR 0022 separately permits distribution with no result.
