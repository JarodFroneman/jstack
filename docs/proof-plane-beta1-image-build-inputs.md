# Beta.1 reviewed image-build inputs

This layer prepares reproducible build contexts; it does not build or qualify
an image. It performs no download, package resolution, Apple `container`
installation or invocation, and it never writes to `.jstack-evals`.

## Repository-controlled inputs

`tools/proof_plane/image_build_inputs.py` validates three checked-in assets:

1. an exact canonical 18-task input plan, including deterministic SHA-256
   digests for the twelve public Tier-1 source tar streams;
2. the complete sorted 52-descriptor MCP document, byte-equal to a local
   `tools/list` probe of the frozen JStack server; and
3. a static Containerfile template that permits only `FROM`, local `ADD`,
   `COPY`, `ENV`, and `WORKDIR`.

The rendered Containerfile has one digest-qualified base, adds only reviewed
uncompressed rootfs tars, and copies the proof runtime after the toolchains so
a component cannot replace it. There is no `RUN`, package-manager command,
URL, build argument, secret, SSH mount, or mutable image tag.

Five generic runtime payloads are ready in the repository and re-hashed for
every matrix: the launcher, tool reporter, grader, JStack MCP server, and exact
52-tool descriptor. The sixth payload, `jstack-proof-canary`, must be a
separately reviewed executable Linux/arm64 ELF compiled from
`tools/proof_plane/isolation_canary.c`; source bytes are not a substitute for
the target binary.

## External reviewed-input layout

The assembly API accepts an arbitrary private `0700` root, outside the real
study artifact tree:

```text
<reviewed-root>/
  global/
    apple-container-builder-lock.json
    apple-container-builder-lock.json.sig
    build-input-reviewer-roster.json
    jstack-proof-canary
  tasks/<exact-task-id>/
    input-lock.json
    components/<exact-component-slot>.tar
    reviews/
      base-license-evidence.json
      base-license-evidence.json.sig
      license-disposition.json
      license-disposition.json.sig
      containerfile-policy-review.json
      containerfile-policy-review.json.sig
```

Assembly separately receives `source_artifact_root`, the private root containing the
canonical `source-artifact-index.json` and its 18 indexed archives. The source
root is not copied into build contexts. Its `source_git_repo` parameter is the
absolute, non-symlink Git work tree whose object database contains every Tier-1
commit named by that index. At each commit, the exact repository-relative
subtree from `TIER1_PROJECTS[*][*]["project"]` must exist. It may be the JStack
repository itself or a separate work tree backed by the same immutable object
database; the current checkout content is never treated as evidence.

Every task lock uses `jstack.eval.image-build-input-lock.v2`; it is closed,
canonical, and self-digested. It binds the source commit and project-tree Git
object, source archive/content and source-index digests,
Linux/arm64 base, exact component versions/digests/source URLs/SPDX IDs,
component-provided tool set, archive member inventory, licence evidence,
aggregate licence disposition, and output repository. Rootfs tars must be
uncompressed, root-owned, epoch-zero, path-sorted POSIX archives without
devices, FIFOs, privilege bits, escaping links, secrets, holdouts, or proof
runtime replacements.

Each component embeds exactly one canonical
`jstack.eval.offline-dependency-inventory.v1` document at the lock-selected
path. The document provides exact tool versions; a sorted package inventory
with exact versions, source URLs, SPDX identifiers, and licence paths; and a
sorted descriptor for every other non-directory tar member. Regular-file
descriptors bind SHA-256 and mode. Symlink and hard-link descriptors bind the
normalized in-root target and mode. The validator requires the inventory to
cover every non-directory member exactly, permits only ancestor directory
entries, resolves every link without cycles or escapes, and requires every
package licence to be its own regular inventoried file. The task-specific
dependency pins are Zod 3.22.4, AnyIO 4.13.0, pytest 9.0.3, HttpClient and
HttpMime 4.2.5, and sqlite-utils 3.6.

For each Tier-1 task, `reconstruct_tier1_source_from_git()` reads the exact
40-character commit, project tree, and blobs through Git object plumbing. It
independently re-hashes each Git object and reconstructs the canonical tar
without reading the mutable checkout. The reconstructed bytes and tree object
must equal the task plan, v2 input lock, and validated source-artifact-index
row. A plausible commit string or an uncommitted checkout is not evidence.
Historical rows remain bound to their reviewed upstream commits and archives.

All review authority comes from the canonical private
`build-input-reviewer-roster.json`. The Apple builder lock, base-image licence
evidence, aggregate licence disposition, and post-render Containerfile-policy
receipt each embed the roster-derived signer digest and require a detached
OpenSSH SSHSIG under the fixed
`jstack-beta1-image-build-input-review-v1` namespace. Production verification
always resolves the system `ssh-keygen`; no verifier path or callback is a
public production parameter, and private signing keys are never opened.

The human Containerfile-policy receipt is produced only after rendering. It
cross-binds the task ID, exact input-lock digest, and rendered Containerfile
digest. Assembly then inventories the context through
`image_foundation.capture_build_context` and seals the full matrix through
`image_foundation.seal_image_build_matrix`.

## Exact task/component inventory

Every image has `common-linux-runtime`, which must provide Python, Git,
bubblewrap, and GNU coreutils. The task-specific second slot, where required,
is fixed below.

| Task ID | Frozen source/base state | Additional component slot |
|---|---|---|
| `typescript-web-local-continuation-seeded` | Tier-1 tar and Git tree fixed; base review missing | `nodejs-toolchain` (`node`, `npm`) |
| `typescript-web-profile-html-clean` | Tier-1 tar and Git tree fixed; base review missing | `nodejs-toolchain` (`node`, `npm`) |
| `python-api-idempotency-tenant-seeded` | Tier-1 tar and Git tree fixed; base review missing | none |
| `python-api-webhook-signature-clean` | Tier-1 tar and Git tree fixed; base review missing | none |
| `java-csharp-service-tenant-document-seeded` | Tier-1 tar and Git tree fixed; base review missing | `dotnet-8-toolchain` (`dotnet`) |
| `java-csharp-service-profile-mass-assignment-clean` | Tier-1 tar and Git tree fixed; base review missing | `dotnet-8-toolchain` (`dotnet`) |
| `c-cpp-system-frame-capacity-seeded` | Tier-1 tar and Git tree fixed; base review missing | `cmake-c-sanitizer-toolchain` (`cc`, `cmake`, `ctest`) |
| `c-cpp-system-decimal-overflow-clean` | Tier-1 tar and Git tree fixed; base review missing | `cmake-c-sanitizer-toolchain` (`cc`, `cmake`, `ctest`) |
| `data-database-tenant-archive-seeded` | Tier-1 tar and Git tree fixed; base review missing | `sqlite-runtime` (`sqlite`) |
| `data-database-email-injection-clean` | Tier-1 tar and Git tree fixed; base review missing | `sqlite-runtime` (`sqlite`) |
| `legacy-repository-config-prefix-seeded` | Tier-1 tar and Git tree fixed; base review missing | `legacy-c-toolchain` (`cc`, `make`) |
| `legacy-repository-token-prefix-clean` | Tier-1 tar and Git tree fixed; base review missing | `legacy-c-toolchain` (`cc`, `make`) |
| `typescript-web-hono-json-charset-replay` | reviewed Hono commit/archive and Bun base fixed | `bun-hono-offline-runtime` (`bun`, locked Hono modules/Zod 3.22.4) |
| `python-api-starlette-path-url-replay` | reviewed Starlette commit/archive and uv base fixed | `uv-starlette-offline-runtime` (`uv`, AnyIO 4.13.0, pytest 9.0.3) |
| `java-service-nanohttpd-content-length-replay` | reviewed NanoHTTPD commit/archive and Maven base fixed | `maven-nanohttpd-offline-runtime` (`java`, `maven`, complete offline repository) |
| `cpp-system-tinyxml2-character-reference-replay` | reviewed tinyxml2 commit/archive and GCC base fixed | `gcc-cxx-sanitizer-toolchain` (`gcc`, C++ frontend, ASan/UBSan) |
| `data-database-sqlite-utils-foreign-key-replay` | reviewed sqlite-utils commit/archive and Python base fixed | `sqlite-utils-offline-runtime` (`sqlite`, newly reviewed Python dependency lock) |
| `legacy-linenoise-history-resize-replay` | reviewed linenoise commit/archive and GCC base fixed | `gcc-c-sanitizer-toolchain` (`gcc`, libc headers, ASan/UBSan) |

## Current readiness: 0/18

All 18 static task slots are defined and locally validated. No production task
context is yet sealable because the reviewed Linux/arm64 canary, signed Apple
builder lock, build-input reviewer roster, closed component archives and
inventories, v2 task locks, signed licence evidence/dispositions, and signed
post-render Containerfile approvals are absent. The twelve Tier-1 source trees
are now fixed at JStack commit
`f397f8c595c2011e1a838ed7c883a57663c83191`; the migrated private source index
proves each task's exact Git tree reconstructs its unchanged sealed archive.
Those tasks still require reviewed digest-pinned bases. The six historical
tasks already have their source commit/archive and base reference fixed, but
still require the base licence evidence and offline toolchain/cache archives
listed above.

`audit_image_build_input_readiness()` returns all 18 task IDs with stable
machine-readable blocker codes. `assemble_image_build_matrix()` preflights the
entire set before writing the first context and removes only contexts it created
if sealing fails. A test-only synthetic reviewed set proves the complete
context-to-foundation join; those fixture bytes and digests are not production
inputs.

`migrate_tier1_source_artifact_index()` is the only production path that
updates an older private Tier-1 index. It requires the exact prior task/commit
map plus prior raw and self digests, reconstructs every target tree from Git,
and proves byte equality with every existing archive before publishing a
canonical backup, migration receipt, and replacement index. It never rewrites
`source.tar` and never accepts a checkout-only substitute.
