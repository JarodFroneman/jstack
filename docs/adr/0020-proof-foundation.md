# ADR 0020: Development-Only Proof Foundation

- Status: Accepted
- Date: 2026-08-12
- Target release: 0.10.0-alpha.10

## Context

JStack has deterministic unit, adversarial, MCP, installation, and synthetic
audit tests, but those checks do not prove how an AI host performs on full
repositories across languages. Adding model clients, benchmark execution, or
vendor scanners to the installed runtime would enlarge JStack's authority and
dependency surface before the evaluation protocol itself is trustworthy.

The existing `jstack.audit.synthetic.v1` corpus contains 12 inert structured
fixtures. It is retained as Tier 0 protocol evidence and must not be described
as a repo-level, multi-language, patch-preservation benchmark.

## Decision

1. Create `evals/` as maintainer infrastructure outside every installed MCP,
   umbrella-plugin, and dedicated-plugin payload.
2. Publish five closed v1 contracts: corpus manifest, runnable task, run
   envelope, blinded human review, and deterministic score.
3. Require runnable tasks to bind exact source, commit, archive digest,
   licence decision, isolated image and tools, network-default, brief,
   baseline, change boundary, budgets, sealed hidden tests, invariants, and an
   expected fixed/refused/blocked outcome.
4. Add only an inert mock host in alpha.10. It executes no repository code,
   fetches no source, calls no host or model API, and opens no network.
5. Score raw metrics and confidence intervals rather than a composite marketing
   score. Failed, blocked, and timed-out runs stay in the denominator. Every
   score must match a closed manifest execution plan exactly so cherry-picked
   subsets cannot silently redefine attempted work.
6. Define paired plain-versus-JStack controlled and operational comparisons.
   Controlled pairs require identical task, host-model-JStack configuration,
   images, toolchains, allowed-tool digests, tool-call limits, and budgets. A
   Codex-versus-Claude result using different models must be called a
   host-model configuration comparison.
7. Declare six families and 18 planned slots—seeded defect, historical replay,
   and clean control for each—without adding unfinished task files or claiming
   results.
8. Lock the development manifest, mock fixture, validators, mock host, scorer,
   and schemas by raw-byte SHA-256.
9. Snapshot alpha.9 public contracts and enforce the permanent five-command,
   52-tool, 11-role, 18-capability, standard-library, no-packaged-evals
   boundary in CI.
10. Keep execution, scanners, adapters, real-host runners, external pilots,
    installer lifecycle work, and signed release artifacts for later measured
    milestones.

## Consequences

- Alpha.10 can prove the harness contracts, scoring arithmetic, compatibility
  floor, complete-run-plan binding, privacy boundary, and anti-bloat
  invariants deterministically.
- It cannot yet prove JStack uplift, vulnerability recall on real code, host
  parity, production incident prevention, or zero-day detection.
- Adding or changing a published alpha.9 v1 contract now fails CI unless a
  deliberate versioned successor and migration are introduced.
- Future benchmark source can live in a content-addressed external cache rather
  than expanding JStack's repository or installed runtime.
- No user workflow, MCP tool, permission, dependency, or release authority is
  added.

## Rejected Alternatives

- A sixth benchmark command: rejected because evaluation is maintainer
  infrastructure, not another delivery workflow.
- Vendor SDKs in core: rejected because established tools should produce native
  artifacts outside JStack and later connect through thin optional evidence
  bridges.
- Publishing mock uplift as product proof: rejected because fabricated ground
  truth and deterministic fixtures cannot measure real model quality.
- Building all 18 repositories in alpha.10: rejected because corpus licensing,
  isolation, holdout governance, reviewer protocol, and host qualification must
  be validated before real results are credible.
