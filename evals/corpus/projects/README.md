# Tier-1 purpose-built projects

This directory contains small, redistributable source projects used only by
the JStack Proof Plane. It is maintainer infrastructure: installers and
packaging must not copy it into the JStack product.

Each project is self-contained, uses the repository's MIT licence, and exposes
one deterministic public test command. The public suites characterize normal
behaviour and stable security invariants; they intentionally do not contain
private holdout cases, answer keys, expected patches, or grader logic.

| Family | Task | Runtime | Public test command |
| --- | --- | --- | --- |
| TypeScript/web | `seeded-defect` | Node.js 22.6+ | `npm test` |
| TypeScript/web | `clean-control` | Node.js 22.6+ | `npm test` |
| Python API | `seeded-defect` | Python 3.9+ | `python3 -m unittest discover -s tests -v` |
| Python API | `clean-control` | Python 3.9+ | `python3 -m unittest discover -s tests -v` |
| Java/C# service | `seeded-defect` | .NET 8 SDK | `dotnet run --project tests/TenantDocuments.Tests.csproj --configuration Release` |
| Java/C# service | `clean-control` | .NET 8 SDK | `dotnet run --project tests/ProfileUpdates.Tests.csproj --configuration Release` |
| C/C++ system | `seeded-defect` | CMake 3.20+ and C11 compiler | `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure` |
| C/C++ system | `clean-control` | CMake 3.20+ and C11 compiler | `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure` |
| Data/database | `seeded-defect` | Python 3.9+ with SQLite | `python3 -m unittest discover -s tests -v` |
| Data/database | `clean-control` | Python 3.9+ with SQLite | `python3 -m unittest discover -s tests -v` |
| Legacy/mixed | `seeded-defect` | Make, Python 3.9+, and C compiler | `make test` |
| Legacy/mixed | `clean-control` | Make, Python 3.9+, and C compiler | `make test` |

The task instructions presented to a model live under
`evals/corpus/public/tasks/`. A green public baseline is necessary, but it is
not proof that a reported edge case is fixed.
