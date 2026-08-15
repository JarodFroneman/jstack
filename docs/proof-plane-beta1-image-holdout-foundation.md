# Beta.1 image and holdout foundation

This foundation closes the declaration layer needed before the 216-run study.
It does not build an image, install Apple `container`, author a hidden test,
execute a grader, or qualify a runtime.

## Image boundary

`tools/proof_plane/image_foundation.py` requires one preregistered matrix with
exactly the 18 reviewed task IDs. Every entry binds:

- Linux/arm64 and a digest-pinned base image;
- the exact source archive, commit, licence, and redistribution status;
- every regular build-context file, mode, size, and SHA-256 digest;
- a separately reviewed Containerfile-policy receipt;
- content-addressed toolchain components, exact versions, provided tool keys,
  source URLs, and SPDX licence identifiers;
- the generic canary, launcher, tool-report, grader, and frozen JStack runtime
  digests; and
- an aggregate licence-disposition receipt.

The only emitted Apple build command is a shell-free argv using
`--platform linux/arm64`, `--no-cache`, a fixed file, tag, and OCI labels. It
does not accept build arguments, secrets, SSH forwarding, or pull flags. Live
runtime and context bytes are re-hashed again when a manifest or task-spec
fragment is created.

Apple `container build` currently exposes no network-off control. Therefore
the manifest says only that an external build result was bound; it is not
offline-build proof. Before a build, the maintainer executor requires every
digest-pinned base reference in the frozen 18-task matrix to exist in the
local image inventory, but this is not a host-egress guarantee. A final digest
is not runnable study evidence until the production qualification layer
admits the closed build and host OCI-inspection receipt chain, finds that exact
local OCI image, and the isolation canary passes.

The Beta.1 local evidence boundary trusts the dedicated maintainer account and
all processes running as that same OS user while building. Private `0700`
roots, a cooperative inter-process lifecycle lock, stable file-descriptor
reads, and pre/post hashes detect accidental and persistent drift; they do not
provide hostile same-user mutate-and-restore resistance or cryptographic proof
that a subprocess ran. Receipts are trusted maintainer/harness attestations
that the independent final evidence verifier must re-check. They must not be
described as hostile-local-actor-safe or independently cryptographic build
attestations.

## Holdout boundary

`tools/proof_plane/holdout_foundation.py` defines a private canonical JSON
bundle. Its cases contain bounded deterministic data for one task-specific,
versioned adapter. The format contains no command, argv, shell, executable,
script, environment, import, module, function, or process selector.

The fixed in-image grader must implement each adapter in reviewed code. It may
return only one typed baseline/candidate outcome for every sealed case plus
bounded public-test, path-boundary, sanitizer, and coverage observations. The
foundation derives the score-bearing vulnerability, patch, regression, hidden
failure, and target-outcome fields; those fields are not caller inputs.

Bundles are atomically created once as mode `0600` files below a mode `0700`
`.jstack-evals` artifact root, using this production grading layout:

```text
.jstack-evals/<study>/task-artifacts/<task-id>/holdout.bundle
```

The raw file SHA-256 is the `hiddenTestBundleSha256` consumed by task specs.
Production grading parses the canonical bundle and checks its task,
family/kind, baseline, source archive/content, grader, expected outcome, and
raw-file digest against the final task descriptor immediately before mounting
it. The grading gate remains solely responsible for delaying that access until
all 216 model attempts have terminal receipts and the model is proven absent.

## Remaining admission blockers

Before final images can qualify, maintainers still need to produce and review:

1. exact content-addressed build contexts and Containerfiles for all 18 tasks;
2. toolchain artifact and licence-disposition receipts;
3. one separately reviewed Linux/arm64 canary binary and the exact offline
   guest execution closure used by the implemented launcher, tool reporter,
   grader, and 18 fixed task adapters;
4. curator-signed private holdout cases and independently reproduced baseline
   receipts through the fixed task-artifact lifecycle;
5. an installed, signed Apple `container` runtime and 18 locally built images;
6. canonical build-execution and OCI-inspection receipts for all 18 images;
7. qualification evidence that independently binds every executable used to
   report the canary and tool versions; and
8. all controller, 216-run terminal, sealed-grading, and human-review gates.

No task descriptor, registration, study result, validation, release-readiness,
or uplift claim may use this declaration foundation as a substitute for those
produced artifacts. ADR 0022 permits an explicitly unvalidated product
prerelease, but that distribution does not alter this evidence boundary.

## Implemented admission integrations

The Beta integration now:

- requires per-task canonical build-execution and host OCI-inspection receipts
  before any qualification subprocess can start;
- cross-checks the manifest, receipt, final image, and all six inspected
  runtime-artifact digests, including the launcher and tool reporter;
- binds the sorted exact task tool set into every launcher argv through
  repeated `--required-tool` arguments;
- records both receipt raw digests in frozen v1 task `toolVersions` metadata
  without changing that public schema;
- validates the private canonical holdout against the final task before
  production grading uses it; and
- reconstructs a deterministic candidate Git commit, mounts that metadata into
  the grader, and rejects a mismatched observed candidate commit.

## Remaining executable and external-evidence blockers

These cannot be satisfied by another caller-supplied digest or by this
non-executing declaration layer:

- Produce the immutable Linux/arm64 canary and complete reviewed guest runtime
  closure. The launcher, exact-set tool reporter, grader, and 18 fixed adapter
  implementations now exist, but qualification remains blocked until the
  inspected image contains those exact bytes and their bound execution TCB.
- Run the production image-build/inspection executor against each sealed
  matrix entry to produce the receipts consumed by the admission hook. A
  declaration-only manifest cannot substitute for those receipts.
- Author genuine private cases under the implemented 18 adapter-specific
  input/output/assertion schemas, sign them with the preregistered curator key,
  and reproduce every baseline in its qualified image. JSON case values remain
  untrusted data and adapter code never treats them as executable selectors.
- Bind model-reported finding identities and attempted-fix evidence into the
  immutable attempt bundle. Without those fields the declarative projector can
  prove successful behavioural repair but cannot independently separate
  “detected”, “attempted”, and “correctly patched” rates.
Until those external artifacts exist and pass adversarial tests, the contracts
remain fail-closed and no runnable study or uplift claim is permitted.
