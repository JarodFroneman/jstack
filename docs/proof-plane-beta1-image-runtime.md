# Beta.1 in-image proof runtime

The Beta.1 task image contains three content-addressed, Python 3.9-compatible,
standard-library executables:

- `jstack-proof-canary-launcher` verifies all six embedded runtime artifacts,
  runs the isolation canary, and requests the exact task tool set with repeated
  `--required-tool` arguments.
- `jstack-proof-tool-report` uses only reviewed absolute version-probe argv,
  including Git. It parses the canonical 52-descriptor MCP document and proves
  that the frozen MCP server advertises exactly the same complete descriptors.
- `jstack-proof-grade` parses one canonical private bundle, selects only a
  reviewed task adapter, reconstructs the captured patch from sealed Git state,
  runs public and hidden checks, and emits one canonical self-digested grader
  observation.

Candidate code never runs in the grader namespace that can see the holdout.
Each public or hidden execution receives a disposable source copy in a nested
bubblewrap namespace. That namespace binds the toolchain, source copy, and
fixed adapter only; `/sealed` is not mounted. Inputs are sent over stdin and
expected values remain in the outer grader process.

## Implemented Tier-1 adapter inputs

The private bundle remains declarative JSON. These are the only accepted input
shapes; none contains an executable selector.

| Task adapter | Fixed input shape |
|---|---|
| TypeScript redirect | `{applicationOrigin, requested}` |
| TypeScript profile rendering | `{displayName}` |
| Python transfer idempotency | `{operations: [{userId, idempotencyKey, amount}]}` |
| Python webhook verification | `{bodyHex, header, secretHex, now}` |
| C# tenant document lookup | `{documents: [{id, tenantId, contents}], tenantId, documentId}` |
| C# profile update | `{json, authenticatedIsAdmin}` |
| C frame decoder | `{frame: [byte...], outputCapacity}` |
| C decimal parser | `{text, initialValue}` |
| SQLite tenant documents | `{rows, tenantId, includeArchived}` |
| SQLite user lookup | `{rows, email}` |
| Legacy configuration lookup | `{contentsUtf8, keyUtf8, outputCapacity}` |
| Legacy token comparison | `{storedHex, suppliedHex}` |

Public commands and build commands are fixed in the executable. The bundle
cannot choose a binary, argument, path, module, environment, or working
directory. Assertions are restricted to `equals`, `not-equals`, `is-true`,
`is-false`, `is-null`, and `is-non-null`.

## Historical replay adapters

All six reviewed replay IDs now have source-specific, behavior-based adapters.
The fixed registry accepts only the following declarative inputs:

| Replay | Fixed input | Observed behavior |
|---|---|---|
| Hono JSON media type | `{body, contentType}` | HTTP status and value produced by the real validator middleware |
| Starlette URL replacement | `{field, url, value}` | Completed replacement plus normalized URL components |
| NanoHTTPD response framing | `{bodyUtf8, explicitContentLength, gzip, transfer}` | Raw framing normalized to status, length headers, transfer headers, and body bytes |
| tinyxml2 character reference | `{observe, xml}` | Per-process completion, parse error code, or decoded text from a debug-and-sanitizer build |
| sqlite-utils foreign key | `{columnName, otherColumnName, otherTableName}` | Foreign-key metadata, retained rows, and `integrity_check` from the real database API |
| linenoise history resize | `{entries, initialMaximum, newMaximum, observe}` | Per-process completion or saved history from an ASan/UBSan-linked characterization driver |

The tinyxml2 and linenoise drivers execute each sealed vector in a child
process. An assertion, sanitizer finding, invalid pointer, timeout, malformed
output, or diagnostic on stderr becomes a failed behavior instead of aborting
the rest of the baseline cases. The bundle still cannot select an executable,
argument, import, environment, or working directory.

The grader treats a historical replay as a fix task, requires every declared
vulnerability to reproduce on the reviewed baseline, and requires all
previously passing behavior to remain passing. It compares patches against the
host-created transport parent in read-only Git metadata; the bundle's upstream
commit remains the independently frozen source identity.

## Required offline image inputs

Qualification must not begin until these task-specific inputs are copied into
the image build context, content-digested, license inventoried, and usable with
network isolation:

- Hono: Bun plus a read-only
  `/usr/local/share/jstack/hono-node_modules` resolved from the reviewed
  `bun.lockb` (the focused validator test requires the locked Zod 3.22.4
  package). The public command links this directory into its disposable source
  copy; the hidden adapter itself imports only upstream Hono source.
- Starlette: the Python environment resolved from the reviewed `uv.lock`,
  including AnyIO 4.13.0 and pytest 9.0.3. `uv` remains a qualified tool, but
  the public and hidden commands use the already-installed environment and do
  not resolve packages during grading.
- NanoHTTPD: a JDK containing `/usr/bin/java` and `/usr/bin/javac`, Maven, and a
  complete read-only offline repository at
  `/usr/local/share/jstack/maven-repository`. That repository must cover the
  parent POM, build extension/plugins, and the core test dependency graph,
  including Apache HttpClient and HttpMime 4.2.5.
- tinyxml2: GCC with a C++ frontend, libstdc++, and working AddressSanitizer and
  UndefinedBehaviorSanitizer runtimes. No package download is used.
- sqlite-utils: an installed, pinned Python environment for the reviewed 3.6
  source and focused tests, including `sqlite-fts4`, Click,
  `click-default-group`, Tabulate, pytest, and the test extras selected for the
  image. These artifacts need a newly reviewed lock because the upstream
  archive predates a complete dependency lock.
- linenoise: GCC, libc development headers (including `strings.h`), and working
  AddressSanitizer and UndefinedBehaviorSanitizer runtimes. No package download
  is used.

The cached source archives already retain their upstream MIT, BSD-3-Clause,
Zlib, Apache-2.0, and BSD-2-Clause license files. Dependency caches must retain
their own notices and a digest-bound inventory; a cache directory without that
license and checksum evidence is not an admissible build input.
