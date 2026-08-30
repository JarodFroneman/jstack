# Graphify-Backed Project Intelligence

JStack Project Intelligence is a private, receipt-bound code-graph subsystem
for understanding and changing existing repositories. It is integrated into
the five delivery workflows and Audit. It adds no slash command, no global
Graphify skill, and no second routing or authority plane.

The subsystem helps an agent select a bounded part of a large codebase before
broad reading, identify likely impact paths, refresh that understanding after
edits, and prove that final evidence covers the exact changed candidate. It
does not replace direct source inspection, tests, linters, scanners, review, or
human judgment.

## Applicability

JStack evaluates applicability from the workflow, normalized goal, repository
languages, and exact changed or proposed paths.

Project Intelligence is mandatory and fails closed for:

- JStack Audit, Subagents, Full Team, Loop, and Program work on a supported
  existing codebase;
- architecture, security, database, dependency, release, migration, and other
  material code goals;
- cross-module changes; and
- an explicit `required` mode.

It may be optional or skipped, with a visible reason, for a genuinely trivial
single-file change or non-code work. It is deferred for a greenfield project
until supported source exists and unsupported when a populated scope contains
no supported language. `off` is accepted only for the narrow trivial boundary;
it cannot disable mandatory routing.

## Lifecycle

1. `jstack_graph_index` classifies applicability and, when required, builds an
   immutable local AST graph before broad source reading. The receipt binds the
   exact repository, starting or supplied change-base commit, HEAD tree, dirty
   fingerprint, JStack policy, provider catalog, graph, and manifest.
2. `jstack_graph_query` selects a deterministic bounded task subgraph from a
   natural-language question. It returns source anchors and an optional private
   Graphify-native HTML view.
3. `jstack_graph_impact` combines the task goal and proposed or actual changed
   paths into a bounded pre-change impact view.
4. After edits, `jstack_graph_refresh` rebuilds the graph explicitly and binds
   a before/after graph delta. JStack installs no repository hook.
5. `jstack_graph_finalize` verifies the exact current candidate, exact Git
   changed paths from the original change base, refreshed graph, direct source
   reads, graph source coverage, tests, independent review, and unresolved
   findings. A passed receipt is required for applicable release readiness.

Planning and Team Composer automatically bind the current index decision and
snapshot. Audit automatically indexes and runs a bounded query. Loop and
Program readiness persist the decision; checkpoints require current refresh
evidence and final acceptance requires current finalization evidence.

## Evidence Authority

Graphify relationships are normalized into one of two authority classes:

- **Strong graph evidence:** an `EXTRACTED` edge with both a valid
  repository-relative `source_file` and a valid source location.
- **Advisory:** every `INFERRED` or `AMBIGUOUS` relationship, plus any
  unanchored `EXTRACTED` relationship.

Advisory relationships may guide exploration but must be verified directly in
source before they support an implementation, audit finding, security claim,
or final review. Even strong graph evidence does not prove runtime behavior or
correctness. Finalization therefore requires direct source and test evidence.

## Private Storage And Visualization

Generated state lives outside the repository at:

```text
~/.jstack/project-intelligence/<repository-id>/
```

Snapshots are immutable, hash-checked, retention-bounded, and referenced by a
private current pointer. Files and directories are current-user private. The
generated `graph.html` is Graphify's static native visualization, contains no
JStack authority, and should be opened for the user when material work is
performed. Focused query and impact views are generated only when their
bounded traversal contains nodes; the full snapshot view remains available.

The HTML and graph are evidence artifacts, not repository source. JStack never
mounts them into the project, commits them, or edits repository instructions.

## Managed Provider

The provider catalog pins:

- package `graphifyy==0.9.52`;
- source repository branch `v8` at commit
  `680e3ed8edd3dc1fa1961050912941880b778207`;
- wheel SHA-256
  `5588ea9af433a8cf74ada89dfc0b981abf596a1327a1375fdaf661905562bf44`;
- local AST extraction and static HTML export only.

Provisioning is an explicit installer option:

```bash
python3 scripts/install.py --with-project-intelligence
```

The installer creates an isolated runtime under
`~/.jstack/tools/graphify/0.9.52/`, verifies the pinned top-level wheel before
installation, verifies the exact CLI version afterward, reuses only a valid
existing runtime, and rolls back a newly created runtime if later JStack
activation fails. The normal installer remains offline with respect to
Graphify.

At runtime JStack launches the executable without a shell, closes stdin,
bounds time and output, uses a disposable private HOME, and forwards no host
API keys or proxy variables. It invokes only:

```text
graphify extract <repository> --no-cluster --code-only --timing
graphify export html --graph <private-graph> --node-limit 5000
```

JStack does not invoke Graphify's assistant installer, hosted service,
semantic API, listener, HTTP MCP mode, skill installer, instruction writer, or
Git-hook setup. Process environment isolation is hardening, not an operating-
system network sandbox. Transitive binary dependencies are resolved by pip at
provisioning time and are not yet represented by a cross-platform hash lock;
that remains a disclosed supply-chain residual risk.

## Failure And Recovery

Mandatory work stops when the managed runtime is absent, the provider version
or catalog drifts, a receipt is stale, the Git tree or dirty fingerprint
changes, a private graph or visualization hash changes, evidence omits exact
changed paths, or final source/test/review requirements fail.

Recovery is explicit: correct the provider installation or evidence, rebuild
the index, rerun bounded impact analysis, refresh after the current edits, and
finalize again. Do not copy an old receipt or treat a graph screenshot as proof
of the current candidate.

## Non-Authority Boundary

Every Project Intelligence response declares `authorityEffect: none`. Indexing
does not authorize reading outside approved scope; impact analysis does not
authorize edits; refresh does not authorize Git actions; finalization does not
authorize release, deployment, production mutation, or external actions.
