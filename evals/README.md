# JStack Proof Plane

`evals/` is development infrastructure for measuring JStack without enlarging
the installed product. It is deliberately outside `mcp/`, `plugin/`, and the
six dedicated command plugins. The installer and artifact synchroniser do not
copy it into Codex.

## Alpha.10 Scope

This release provides only the proof foundation:

- five closed JSON contracts for a corpus, task, run, blinded human review,
  and deterministic score;
- a network-free mock host and scorer implemented with the Python standard
  library;
- a public development manifest covering six project families and 18 planned
  task slots;
- manifest-bound execution plans that enumerate every expected run before
  scoring, so omitted failures cannot disappear from a denominator;
- raw-count, confidence-interval, regression, coverage, cost, time, review,
  and paired-uplift calculations;
- a content lock for the schemas, public manifest, mock fixture, validators,
  mock host, and scorer.

The existing `jstack.audit.synthetic.v1` corpus remains Tier 0. It is a useful
12-fixture protocol regression corpus, not a repository-level model benchmark.
The alpha.10 mock fixture similarly proves the harness plumbing and arithmetic;
it is not evidence that JStack beats plain prompting or that one host beats
another.

## Beta.1 Study Boundary

Beta.1 is the first real Codex study milestone. Its study-validation and claim
gate is deliberately larger than its implementation and distribution gate:
runner code and task fixtures are not a result. A validated study or any
performance, uplift, or release-readiness claim requires all of the following
to exist and verify together:

- 18 qualified tasks across the six declared families;
- one immutable, published, preregistered 216-cell execution plan;
- 216 write-once terminal model attempts, including every failure, blocker,
  and timeout;
- hidden grading performed in fresh VMs only after all attempts terminate;
- 432 cryptographically verified, blinded primary human reviews and every
  required distinct adjudication;
- 216 complete private evidence chains projected into minimized public run,
  review, and attestation documents;
- one canonical private-evidence verification-set receipt proving all private
  chains and human signatures were re-verified, including pair-wide
  adjudicator independence, plus a detached OpenSSH signature from the
  separately preregistered evidence-verifier key; and
- exact scorer reconciliation plus an honest limitations/gap report.

Preregistration also binds a deterministic harness lock covering every direct
`tools/proof_plane` implementation file and every eval runner, schema, and
protocol file. The lock excludes only its own JSON to avoid a hash cycle; its
raw digest is bound in the registration. Missing or added harness files,
symlinks, traversal, duplicate paths, and byte drift all fail closed.

Controlled mode exposes the same four Proof-broker tools to both conditions
and measures workflow-protocol uplift. Operational mode separately compares
the plain broker surface with the broker plus the exact frozen 52-tool JStack
MCP. Neither mode gains network, host, secret, hidden-test, GitHub, deployment,
or production authority.

The current maintainer tooling must fail closed while a qualified container VM,
final task images, immutable registration, private holdouts, or the human
review roster is absent. See [ADR 0021](../docs/adr/0021-beta1-codex-proof-study.md)
and the [reviewed task-artifact lifecycle](../docs/proof-plane-beta1-task-artifact-lifecycle.md).
ADR 0022 permits the exact Beta.1 product bytes to be distributed separately
as an explicitly unvalidated GitHub prerelease and Codex installation. That
distribution does not complete this study, populate its denominator, or turn
its absent evidence into a result.

## Local Verification

Run from the repository root:

```text
python3 -m evals.runner.cli verify-lock
python3 -m evals.runner.cli validate evals/corpus/public/manifest.v1.json
python3 -m evals.runner.cli mock-run evals/fixtures/mock/scenario.v1.json
```

The scorer consumes already-produced structured envelopes. It never fetches a
repository, calls a model or vendor API, executes project code, opens a network
connection, reads an answer key, or changes a project. Future real-project
runners must place execution in ephemeral containers or microVMs and retain
failed, blocked, and timed-out runs in the denominator.

The generic scorer requires a manifest whose closed execution plan exactly
matches the supplied run set. Public plans must cover all 18 family/task-kind
slots, both controlled and operational modes, plain/JStack pairs, and at least
three repetitions per condition. Host, model, JStack version, image, toolchain,
allowed-tool set, tool-call limit, source baseline, holdout, and task bindings
cannot drift within a comparison.

## Metric Boundary

The v1 score reports:

- task completion only when execution completed, blockers passed, and blinded
  human review accepted the run;
- vulnerability recall and correct-patch rate from known ground truth;
- false-discovery and clean-case false-blocker rates;
- task and assertion regressions;
- line, branch, and mutation-coverage deltas;
- model, compute, review-cost, token, tool-call, active-time, queue-time, and
  wall-clock evidence;
- post-handoff review escapes and verified risks intercepted before merge;
- paired JStack-versus-plain completion differences for controlled and
  operational runs.

Overall metrics are repeated as plain and JStack condition breakdowns so
quality, cost, tokens, timing, and review outcomes remain comparable. Rates
include raw numerator/denominator counts and recomputed Wilson 95% intervals.
Paired uplift uses a conservative distribution-free Hoeffding interval when
at least two valid pairs exist; a small identical sample therefore cannot
pretend to have zero uncertainty. No single marketing score is produced.

## Privacy And Integrity

Run envelopes prohibit source, prompts, model output, command output, and human
identity. Human reviewers are represented by pseudonymous digests. The public
manifest contains no private repository details. Each score binds the exact
manifest, run set, and review set, and rejects missing or extra expected runs.
The corpus lock binds raw
bytes for every alpha.10 schema, the public manifest, the mock fixture, and the
code that validates, produces, and scores mock runs. It rejects missing,
changed, duplicate, traversing, or symlinked entries.

Real tasks are intentionally absent from alpha.10. Before a task can be made
runnable it must bind an exact upstream repository and commit, source archive
digest, licence decision, isolated image and tools, brief and baseline digests,
change boundaries, budgets, a sealed hidden-test digest, security and behaviour
invariants, and one expected outcome: fixed, safely refused, or correctly
blocked.

## Permanent Product Boundary

Proof Plane work must not add a sixth command, an MCP tool, a core dependency,
a vendor SDK, a network-enabled importer, a role, or new external authority.
Vendor tools may later execute outside JStack and feed native evidence through
optional bridges; their SDKs and execution logic do not belong in core.
