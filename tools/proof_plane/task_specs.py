"""Create closed public task descriptors from reviewed Beta.1 task specs.

The image references recorded in :data:`HISTORICAL_REPLAYS` are upstream base
images only.  They are useful inputs to the reproducible image build, but are
not qualified task environments.  A runnable descriptor can be created only
after the caller supplies the digest of a purpose-built final image, the
digest of its build manifest, and the exact versions observed by the image
qualification canary.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS, validate_task

from .common import (
    ProofPlaneError,
    canonical_digest,
    exact_fields,
    file_digest,
    resolve_within,
)


COMMON_QUALIFIED_TOOLS = [
    "python",
    "git",
    "bubblewrap",
    "coreutils",
    "jstack-proof-canary-version",
    "jstack-proof-canary-sha256",
    "jstack-proof-canary-launcher-sha256",
    "jstack-proof-tool-report-sha256",
    "jstack-proof-grader-version",
    "jstack-proof-grader-sha256",
    "jstack-proof-runtime-sha256",
    "jstack-mcp-server-sha256",
    "jstack-mcp-tools-sha256",
    "jstack-mcp-tool-count",
]


HISTORICAL_REPLAYS: dict[str, dict[str, Any]] = {
    "typescript-web": {
        "taskId": "typescript-web-hono-json-charset-replay",
        "source": {
            "upstreamRepository": "https://github.com/honojs/hono",
            "upstreamCommit": "0417830fe9f82430b53073a443930a4e9e052398",
            "sourceArchiveSha256": "1e9178382df97c7f7381dbd09ce2438e9f2bd01f708ad33710dedad006e51f61",
            "licenseSpdx": "MIT",
            "redistribution": "cache-only",
        },
        "baseImageReference": "docker.io/oven/bun@sha256:9f7d3396b847e23248b266a94be367f4b3bb00cae7b6f1232d7b5fef6de92dd7",
        "requiredQualifiedTools": [
            "bun",
            *COMMON_QUALIFIED_TOOLS,
        ],
        "brief": "evals/corpus/public/tasks/typescript-web/historical-replay/brief.md",
        "allowed": ["src/validator"],
        "forbidden": ["proof-holdout", "test/hidden"],
        "maxFiles": 6,
        "invariants": {
            "security": ["Non-JSON media types remain unparsed as JSON"],
            "compatibility": ["Ordinary application/json and structured +json handling remain compatible"],
            "regression": ["Focused validator suite and charset=utf-8 behaviour remain passing"],
        },
    },
    "python-api": {
        "taskId": "python-api-starlette-path-url-replay",
        "source": {
            "upstreamRepository": "https://github.com/Kludex/starlette",
            "upstreamCommit": "4a18cd4a0869158f830e9bf519979d6f6f60f36a",
            "sourceArchiveSha256": "8a820b05073fd1a24772fc828f865a25b4b10f7e2d5c876e4fbceac2e4ba961a",
            "licenseSpdx": "BSD-3-Clause",
            "redistribution": "cache-only",
        },
        "baseImageReference": "ghcr.io/astral-sh/uv@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca",
        "requiredQualifiedTools": [
            "uv",
            *COMMON_QUALIFIED_TOOLS,
        ],
        "brief": "evals/corpus/public/tasks/python-api/historical-replay/brief.md",
        "allowed": ["starlette/datastructures.py", "tests/test_datastructures.py"],
        "forbidden": ["proof-holdout", "tests/hidden"],
        "maxFiles": 4,
        "invariants": {
            "security": ["URL components are escaped and reconstructed without index failures"],
            "compatibility": ["Hostname, IPv6, port, path, and query replacement semantics remain compatible"],
            "regression": ["Focused data-structure suite remains passing"],
        },
    },
    "java-csharp-service": {
        "taskId": "java-service-nanohttpd-content-length-replay",
        "source": {
            "upstreamRepository": "https://github.com/NanoHttpd/nanohttpd",
            "upstreamCommit": "1de83fe8f6f0164e52b14dbafda876e181ce383d",
            "sourceArchiveSha256": "47d770774ee1b8c0f2af716532d829ecf7b54e034233a515d09c52f6fe77c550",
            "licenseSpdx": "BSD-3-Clause",
            "redistribution": "cache-only",
        },
        "baseImageReference": "docker.io/library/maven@sha256:e3c149f44c95b0e9dd131862b3df67b3f061f7f6f3898a87b170564b3a943611",
        "requiredQualifiedTools": [
            "java",
            "maven",
            *COMMON_QUALIFIED_TOOLS,
        ],
        "brief": "evals/corpus/public/tasks/java-csharp-service/historical-replay/brief.md",
        "allowed": ["core/src/main", "core/src/test"],
        "forbidden": ["proof-holdout", "target"],
        "maxFiles": 4,
        "invariants": {
            "security": ["Response framing emits no conflicting duplicate length header"],
            "compatibility": ["Fixed, streaming, chunked, and body-length semantics remain compatible"],
            "regression": ["All 165 core tests remain passing"],
        },
    },
    "c-cpp-system": {
        "taskId": "cpp-system-tinyxml2-character-reference-replay",
        "source": {
            "upstreamRepository": "https://github.com/leethomason/tinyxml2",
            "upstreamCommit": "d418ac22f204b663880a37ebbb82996dc020f603",
            "sourceArchiveSha256": "92aa5ea1d465a6ddfbe46f27df3f7b816d8a9a43969ddf85a1844975be47d640",
            "licenseSpdx": "Zlib",
            "redistribution": "cache-only",
        },
        "baseImageReference": "docker.io/library/gcc@sha256:b99b86a28812b1e6453a231a947dc43d76fe192788a12f344a9b568bf9f5d24c",
        "requiredQualifiedTools": [
            "gcc",
            *COMMON_QUALIFIED_TOOLS,
        ],
        "brief": "evals/corpus/public/tasks/c-cpp-system/historical-replay/brief.md",
        "allowed": ["tinyxml2.cpp", "tinyxml2.h", "xmltest.cpp"],
        "forbidden": ["proof-holdout", "build"],
        "maxFiles": 4,
        "invariants": {
            "security": ["Malformed numeric references cause no assertion or memory-safety failure"],
            "compatibility": ["Valid decimal and hexadecimal entity decoding remains compatible"],
            "regression": ["Debug and normal upstream suites remain passing"],
        },
    },
    "data-database": {
        "taskId": "data-database-sqlite-utils-foreign-key-replay",
        "source": {
            "upstreamRepository": "https://github.com/simonw/sqlite-utils",
            "upstreamCommit": "16987bd56ef04ed1f1629b58272d8592c3a13249",
            "sourceArchiveSha256": "e4e5fe835fce279523cb41078e81268dbd5322087996894bca717db626b34be3",
            "licenseSpdx": "Apache-2.0",
            "redistribution": "cache-only",
        },
        "baseImageReference": "docker.io/library/python@sha256:bf3ec573c0ae0d0c619c3f3e0e9490878432bf7a5c63a643b6c39c9878b51191",
        "requiredQualifiedTools": [
            "sqlite",
            *COMMON_QUALIFIED_TOOLS,
        ],
        "brief": "evals/corpus/public/tasks/data-database/historical-replay/brief.md",
        "allowed": ["sqlite_utils", "tests"],
        "forbidden": ["proof-holdout", "dist"],
        "maxFiles": 6,
        "invariants": {
            "security": ["Schema reconstruction quotes user-controlled identifiers safely"],
            "compatibility": ["Foreign-key metadata and existing data remain compatible"],
            "regression": ["PRAGMA integrity_check returns ok and focused tests pass"],
        },
    },
    "legacy-repository": {
        "taskId": "legacy-linenoise-history-resize-replay",
        "source": {
            "upstreamRepository": "https://github.com/antirez/linenoise",
            "upstreamCommit": "5654f543aa418522b80c96ecd1fa55dd5801832a",
            "sourceArchiveSha256": "11f0b68a9014df2592426c70953340408d053e271dc066a24c19ddc19443261d",
            "licenseSpdx": "BSD-2-Clause",
            "redistribution": "cache-only",
        },
        "baseImageReference": "docker.io/library/gcc@sha256:a3e091325c0af43bc9c1c576ddd155351d5b16438124421188bb4b4fcacc1452",
        "requiredQualifiedTools": [
            "gcc",
            *COMMON_QUALIFIED_TOOLS,
        ],
        "brief": "evals/corpus/public/tasks/legacy-repository/historical-replay/brief.md",
        "allowed": ["linenoise.c", "linenoise.h", "proof_tests"],
        "forbidden": ["proof-holdout", "history.txt"],
        "maxFiles": 5,
        "invariants": {
            "security": ["History resize creates no invalid pointer, leak, or out-of-bounds access"],
            "compatibility": ["Saved history ordering and newest-entry retention remain compatible"],
            "regression": ["Sanitizer-backed characterization and example build remain passing"],
        },
    },
}


TIER1_PROJECTS: dict[str, dict[str, dict[str, Any]]] = {
    "typescript-web": {
        "seeded-defect": {
            "taskId": "typescript-web-local-continuation-seeded",
            "project": "evals/corpus/projects/typescript-web/seeded-defect",
            "files": (
                "README.md",
                "package.json",
                "src/redirect.ts",
                "tests/redirect.test.ts",
            ),
            "requiredQualifiedTools": ["node", "npm", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/typescript-web/seeded-defect/brief.md",
            "allowed": ["src/redirect.ts", "tests/redirect.test.ts"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Cross-origin, malformed, and non-HTTP continuations never redirect externally"],
                "compatibility": ["Accepted local and same-origin destinations preserve path, query, and fragment"],
                "regression": ["The deterministic Node.js public suite remains passing"],
            },
        },
        "clean-control": {
            "taskId": "typescript-web-profile-html-clean",
            "project": "evals/corpus/projects/typescript-web/clean-control",
            "files": (
                "README.md",
                "package.json",
                "src/profile.ts",
                "tests/profile.test.ts",
            ),
            "requiredQualifiedTools": ["node", "npm", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/typescript-web/clean-control/brief.md",
            "allowed": ["src/profile.ts", "tests/profile.test.ts"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Attacker-controlled display names cannot introduce executable HTML"],
                "compatibility": ["Ordinary display text is encoded exactly once"],
                "regression": ["A false report produces no unnecessary source change and the public suite passes"],
            },
        },
    },
    "python-api": {
        "seeded-defect": {
            "taskId": "python-api-idempotency-tenant-seeded",
            "project": "evals/corpus/projects/python-api/seeded-defect",
            "files": (
                "README.md",
                "src/__init__.py",
                "src/transfers.py",
                "tests/test_transfers.py",
            ),
            "requiredQualifiedTools": ["python", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/python-api/seeded-defect/brief.md",
            "allowed": ["src/transfers.py", "tests/test_transfers.py"],
            "maxFiles": 2,
            "invariants": {
                "security": ["An idempotency key cannot disclose or replay another user's transfer"],
                "compatibility": ["Same-user retries return the original transfer and validation remains stable"],
                "regression": ["The deterministic Python public suite remains passing"],
            },
        },
        "clean-control": {
            "taskId": "python-api-webhook-signature-clean",
            "project": "evals/corpus/projects/python-api/clean-control",
            "files": (
                "README.md",
                "src/__init__.py",
                "src/webhooks.py",
                "tests/test_webhooks.py",
            ),
            "requiredQualifiedTools": ["python", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/python-api/clean-control/brief.md",
            "allowed": ["src/webhooks.py", "tests/test_webhooks.py"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Modified and stale webhook messages fail verification"],
                "compatibility": ["Documented signatures within the replay window remain accepted"],
                "regression": ["A false report produces no unnecessary source change and the public suite passes"],
            },
        },
    },
    "java-csharp-service": {
        "seeded-defect": {
            "taskId": "java-csharp-service-tenant-document-seeded",
            "project": "evals/corpus/projects/java-csharp-service/seeded-defect",
            "files": (
                "README.md",
                "src/TenantDocumentService.cs",
                "src/TenantDocuments.csproj",
                "tests/Program.cs",
                "tests/TenantDocuments.Tests.csproj",
            ),
            "requiredQualifiedTools": ["dotnet", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/java-csharp-service/seeded-defect/brief.md",
            "allowed": ["src/TenantDocumentService.cs", "tests/Program.cs"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Document lookup is bound to both document identifier and authenticated tenant"],
                "compatibility": ["Missing and foreign-tenant documents share the same not-found result"],
                "regression": ["The deterministic .NET public suite remains passing"],
            },
        },
        "clean-control": {
            "taskId": "java-csharp-service-profile-mass-assignment-clean",
            "project": "evals/corpus/projects/java-csharp-service/clean-control",
            "files": (
                "README.md",
                "src/ProfileUpdateService.cs",
                "src/ProfileUpdates.csproj",
                "tests/ProfileUpdates.Tests.csproj",
                "tests/Program.cs",
            ),
            "requiredQualifiedTools": ["dotnet", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/java-csharp-service/clean-control/brief.md",
            "allowed": ["src/ProfileUpdateService.cs", "tests/Program.cs"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Profile JSON cannot assign server-owned privilege state"],
                "compatibility": ["Supported profile fields retain their documented update behaviour"],
                "regression": ["A false report produces no unnecessary source change and the public suite passes"],
            },
        },
    },
    "c-cpp-system": {
        "seeded-defect": {
            "taskId": "c-cpp-system-frame-capacity-seeded",
            "project": "evals/corpus/projects/c-cpp-system/seeded-defect",
            "files": (
                "CMakeLists.txt",
                "README.md",
                "include/frame_decoder.h",
                "src/frame_decoder.c",
                "tests/test_frame_decoder.c",
            ),
            "requiredQualifiedTools": ["cmake", "ctest", "cc", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/c-cpp-system/seeded-defect/brief.md",
            "allowed": ["include/frame_decoder.h", "src/frame_decoder.c", "tests/test_frame_decoder.c"],
            "maxFiles": 3,
            "invariants": {
                "security": ["Exact-capacity frames cannot write outside the caller's buffer"],
                "compatibility": ["Valid frames remain decoded and NUL terminated"],
                "regression": ["Public tests and the qualified sanitizer suite remain passing"],
            },
        },
        "clean-control": {
            "taskId": "c-cpp-system-decimal-overflow-clean",
            "project": "evals/corpus/projects/c-cpp-system/clean-control",
            "files": (
                "CMakeLists.txt",
                "README.md",
                "include/decimal_counter.h",
                "src/decimal_counter.c",
                "tests/test_decimal_counter.c",
            ),
            "requiredQualifiedTools": ["cmake", "ctest", "cc", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/c-cpp-system/clean-control/brief.md",
            "allowed": ["include/decimal_counter.h", "src/decimal_counter.c", "tests/test_decimal_counter.c"],
            "maxFiles": 3,
            "invariants": {
                "security": ["Overflow, signs, suffixes, and empty decimal counters remain rejected"],
                "compatibility": ["Canonical values through UINT32_MAX remain accepted"],
                "regression": ["A false report produces no unnecessary source change and qualified tests pass"],
            },
        },
    },
    "data-database": {
        "seeded-defect": {
            "taskId": "data-database-tenant-archive-seeded",
            "project": "evals/corpus/projects/data-database/seeded-defect",
            "files": (
                "README.md",
                "schema.sql",
                "src/__init__.py",
                "src/documents.py",
                "tests/test_documents.py",
            ),
            "requiredQualifiedTools": ["python", "sqlite", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/data-database/seeded-defect/brief.md",
            "allowed": ["src/documents.py", "tests/test_documents.py"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Default and archived queries return rows only for the authenticated tenant"],
                "compatibility": ["Archived-row inclusion and stable ordering semantics remain compatible"],
                "regression": ["The deterministic SQLite public suite remains passing"],
            },
        },
        "clean-control": {
            "taskId": "data-database-email-injection-clean",
            "project": "evals/corpus/projects/data-database/clean-control",
            "files": (
                "README.md",
                "schema.sql",
                "src/__init__.py",
                "src/users.py",
                "tests/test_users.py",
            ),
            "requiredQualifiedTools": ["python", "sqlite", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/data-database/clean-control/brief.md",
            "allowed": ["src/users.py", "tests/test_users.py"],
            "maxFiles": 2,
            "invariants": {
                "security": ["Crafted email values cannot alter query structure or enumerate other rows"],
                "compatibility": ["Exact email lookup remains parameterized and schema semantics remain stable"],
                "regression": ["A false report produces no unnecessary source change and the SQLite suite passes"],
            },
        },
    },
    "legacy-repository": {
        "seeded-defect": {
            "taskId": "legacy-repository-config-prefix-seeded",
            "project": "evals/corpus/projects/legacy-repository/seeded-defect",
            "files": (
                "Makefile",
                "README.md",
                "include/legacy_config.h",
                "src/legacy_config.c",
                "tests/test_legacy_config.py",
            ),
            "requiredQualifiedTools": ["python", "make", "cc", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/legacy-repository/seeded-defect/brief.md",
            "allowed": ["include/legacy_config.h", "src/legacy_config.c", "tests/test_legacy_config.py"],
            "maxFiles": 3,
            "invariants": {
                "security": ["Configuration lookup matches complete keys rather than attacker-controlled prefixes"],
                "compatibility": ["Comments, line ordering, and ordinary exact lookups remain compatible"],
                "regression": ["The deterministic legacy characterization suite remains passing"],
            },
        },
        "clean-control": {
            "taskId": "legacy-repository-token-prefix-clean",
            "project": "evals/corpus/projects/legacy-repository/clean-control",
            "files": (
                "Makefile",
                "README.md",
                "include/legacy_token.h",
                "src/legacy_token.c",
                "tests/test_legacy_token.py",
            ),
            "requiredQualifiedTools": ["python", "make", "cc", *COMMON_QUALIFIED_TOOLS],
            "brief": "evals/corpus/public/tasks/legacy-repository/clean-control/brief.md",
            "allowed": ["include/legacy_token.h", "src/legacy_token.c", "tests/test_legacy_token.py"],
            "maxFiles": 3,
            "invariants": {
                "security": ["Prefix, suffix, and wrong-byte tokens never authenticate"],
                "compatibility": ["Equal tokens retain fixed-work comparison over equal-length inputs"],
                "regression": ["A false report produces no unnecessary source change and characterization passes"],
            },
        },
    },
}


def _image_digest(reference: str) -> str:
    marker = "@sha256:"
    if (
        not isinstance(reference, str)
        or not reference
        or len(reference) > 500
        or reference != reference.strip()
        or any(char.isspace() for char in reference)
        or marker not in reference
        or reference.count(marker) != 1
    ):
        raise ProofPlaneError("task image must use one exact OCI digest reference")
    repository, digest = reference.split(marker, 1)
    if not repository or "/" not in repository or repository.endswith(("/", ":")):
        raise ProofPlaneError("task image must use one exact OCI digest reference")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ProofPlaneError("task image reference must contain a lowercase SHA-256 digest")
    return digest


def _artifact_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise ProofPlaneError("%s requires a reviewed lowercase SHA-256 digest" % field)
    return value


def _qualified_tool_versions(value: Any, *, required: list[str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value or not all(isinstance(key, str) for key in value):
        raise ProofPlaneError("qualifiedToolVersions must be a non-empty string-keyed object")
    if set(value) != set(required):
        missing = sorted(set(required) - set(value))
        extra = sorted(set(value) - set(required))
        detail = []
        if missing:
            detail.append("missing %s" % ", ".join(missing))
        if extra:
            detail.append("unknown %s" % ", ".join(extra))
        raise ProofPlaneError("qualifiedToolVersions has %s" % "; ".join(detail))
    placeholders = {
        "latest",
        "unknown",
        "unqualified",
        "placeholder",
        "pending",
        "pinned-image",
        "qualified-image-build",
        "tbd",
    }
    normalized: dict[str, str] = {}
    for name in required:
        version = value[name]
        if (
            not isinstance(version, str)
            or not version
            or len(version) > 128
            or version != version.strip()
            or version.lower() in placeholders
        ):
            raise ProofPlaneError(
                "qualifiedToolVersions.%s must be an exact canary-observed version, not a placeholder" % name
            )
        normalized[name] = version
    if normalized.get("jstack-proof-canary-version") != "jstack-proof-canary-v1":
        raise ProofPlaneError("qualified task images must carry jstack-proof-canary-v1")
    if normalized.get("jstack-proof-grader-version") != "jstack-proof-grader-v1":
        raise ProofPlaneError("qualified task images must carry jstack-proof-grader-v1")
    for digest_field in (
        "jstack-proof-canary-sha256",
        "jstack-proof-canary-launcher-sha256",
        "jstack-proof-tool-report-sha256",
        "jstack-proof-grader-sha256",
        "jstack-proof-runtime-sha256",
        "jstack-mcp-server-sha256",
        "jstack-mcp-tools-sha256",
    ):
        _reviewed_artifact_digest(
            normalized[digest_field],
            "qualifiedToolVersions.%s" % digest_field,
        )
    if normalized.get("jstack-mcp-tool-count") != "52":
        raise ProofPlaneError("qualified task images must carry the exact 52-tool JStack MCP surface")
    return normalized


def _reviewed_artifact_digest(value: Any, field: str) -> str:
    digest = _artifact_digest(value, field)
    if len(set(digest)) == 1:
        raise ProofPlaneError("%s must be a real content digest, not a placeholder" % field)
    return digest


def _source_commit(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(char not in "0123456789abcdef" for char in value)
        or len(set(value)) == 1
    ):
        raise ProofPlaneError("sourceCommit must be a real full lowercase Git commit")
    return value


def _tier1_spec(family: str, task_kind: str) -> dict[str, Any]:
    if family not in TIER1_PROJECTS:
        raise ProofPlaneError("unknown Tier-1 family %r" % family)
    if task_kind not in ("seeded-defect", "clean-control"):
        raise ProofPlaneError("Tier-1 task kind must be seeded-defect or clean-control")
    try:
        return TIER1_PROJECTS[family][task_kind]
    except KeyError as exc:
        raise ProofPlaneError("missing reviewed Tier-1 project for %s/%s" % (family, task_kind)) from exc


def _sealed_test_path(relative: str) -> bool:
    normalized = relative.lower().replace("_", "-").replace(".", "-")
    tokens = tuple(token for token in normalized.split("/") if token)
    return any(
        token == "hidden"
        or token.startswith("hidden-")
        or token == "holdout"
        or token.startswith("holdout-")
        or token == "answer-key"
        or token.startswith("answer-key-")
        for token in tokens
    )


def _tier1_project_manifest(family: str, task_kind: str, *, repo_root: Path) -> dict[str, Any]:
    spec = _tier1_spec(family, task_kind)
    project = resolve_within(repo_root, spec["project"], "Tier-1 project")
    if project.is_symlink() or not project.is_dir():
        raise ProofPlaneError("Tier-1 project must be a regular, non-symlink directory")

    expected_files = tuple(sorted(spec["files"]))
    if len(expected_files) != len(set(expected_files)):
        raise ProofPlaneError("Tier-1 project file inventory contains duplicates")
    if any(_sealed_test_path(relative) for relative in expected_files):
        raise ProofPlaneError("Tier-1 public projects must not contain hidden tests or answer keys")
    expected_directories = sorted(
        {
            parent.as_posix()
            for relative in expected_files
            for parent in Path(relative).parents
            if parent.as_posix() != "."
        }
    )

    actual_files = []
    actual_directories = []
    for candidate in sorted(project.rglob("*")):
        relative = candidate.relative_to(project).as_posix()
        if candidate.is_symlink():
            raise ProofPlaneError("Tier-1 project content must not contain symlinks: %s" % relative)
        if _sealed_test_path(relative):
            raise ProofPlaneError("Tier-1 public projects must not contain hidden tests or answer keys")
        if candidate.is_dir():
            actual_directories.append(relative)
            continue
        if not candidate.is_file():
            raise ProofPlaneError("Tier-1 project content must contain only regular files: %s" % relative)
        actual_files.append(relative)

    if tuple(actual_files) != expected_files or actual_directories != expected_directories:
        missing = sorted(set(expected_files) - set(actual_files))
        unknown = sorted(set(actual_files) - set(expected_files))
        missing_directories = sorted(set(expected_directories) - set(actual_directories))
        unknown_directories = sorted(set(actual_directories) - set(expected_directories))
        detail = []
        if missing:
            detail.append("missing %s" % ", ".join(missing))
        if unknown:
            detail.append("unreviewed %s" % ", ".join(unknown))
        if missing_directories:
            detail.append("missing directories %s" % ", ".join(missing_directories))
        if unknown_directories:
            detail.append("unreviewed directories %s" % ", ".join(unknown_directories))
        raise ProofPlaneError("Tier-1 project file inventory has %s" % "; ".join(detail))

    files = []
    for relative in expected_files:
        path = resolve_within(project, relative, "Tier-1 project file")
        files.append({"path": relative, "sha256": file_digest(path)})
    return {
        "schemaVersion": "jstack.eval.tier1-project-content.v1",
        "projectPath": spec["project"],
        "files": files,
    }


def tier1_project_content_digest(
    family: str,
    task_kind: str,
    *,
    repo_root: Path,
) -> str:
    """Digest the exact, symlink-free public source inventory for one Tier-1 task."""

    return canonical_digest(_tier1_project_manifest(family, task_kind, repo_root=repo_root))


def tier1_task(
    family: str,
    task_kind: str,
    *,
    repo_root: Path,
    artifact_digests: Mapping[str, Any],
) -> dict[str, Any]:
    """Create one qualified Tier-1 descriptor without mutating or freezing a manifest."""

    spec = _tier1_spec(family, task_kind)
    if not isinstance(artifact_digests, Mapping):
        raise ProofPlaneError("Tier-1 task qualification artifacts must be an object")
    exact_fields(
        artifact_digests,
        (
            "sourceCommit",
            "sourceArchiveSha256",
            "sourceContentSha256",
            "projectContentSha256",
            "baselineResultSha256",
            "hiddenTestBundleSha256",
            "finalImageReference",
            "finalImageDigest",
            "qualifiedToolVersions",
            "imageBuildManifestSha256",
            "imageBuildReceiptSha256",
            "imageArtifactInspectionReceiptSha256",
            "imageQualificationResultSha256",
        ),
        "Tier-1 task qualification artifacts",
    )
    commit = _source_commit(artifact_digests["sourceCommit"])
    source_archive_digest = _reviewed_artifact_digest(
        artifact_digests["sourceArchiveSha256"], "sourceArchiveSha256"
    )
    source_content_digest = _reviewed_artifact_digest(
        artifact_digests["sourceContentSha256"], "sourceContentSha256"
    )
    expected_project_digest = tier1_project_content_digest(
        family,
        task_kind,
        repo_root=repo_root,
    )
    project_digest = _reviewed_artifact_digest(
        artifact_digests["projectContentSha256"], "projectContentSha256"
    )
    if project_digest != expected_project_digest:
        raise ProofPlaneError("projectContentSha256 does not match the reviewed Tier-1 source tree")
    baseline_digest = _reviewed_artifact_digest(
        artifact_digests["baselineResultSha256"], "baselineResultSha256"
    )
    holdout_digest = _reviewed_artifact_digest(
        artifact_digests["hiddenTestBundleSha256"], "hiddenTestBundleSha256"
    )
    build_manifest_digest = _reviewed_artifact_digest(
        artifact_digests["imageBuildManifestSha256"], "imageBuildManifestSha256"
    )
    build_receipt_digest = _reviewed_artifact_digest(
        artifact_digests["imageBuildReceiptSha256"], "imageBuildReceiptSha256"
    )
    inspection_receipt_digest = _reviewed_artifact_digest(
        artifact_digests["imageArtifactInspectionReceiptSha256"],
        "imageArtifactInspectionReceiptSha256",
    )
    qualification_result_digest = _reviewed_artifact_digest(
        artifact_digests["imageQualificationResultSha256"], "imageQualificationResultSha256"
    )
    final_reference = artifact_digests["finalImageReference"]
    if not isinstance(final_reference, str):
        raise ProofPlaneError("finalImageReference must be a digest-qualified OCI reference")
    final_digest = _reviewed_artifact_digest(artifact_digests["finalImageDigest"], "finalImageDigest")
    if _image_digest(final_reference) != final_digest:
        raise ProofPlaneError("finalImageReference and finalImageDigest do not match")
    if final_digest in {
        source_archive_digest,
        source_content_digest,
        project_digest,
        baseline_digest,
        holdout_digest,
        build_manifest_digest,
        build_receipt_digest,
        inspection_receipt_digest,
        qualification_result_digest,
    }:
        raise ProofPlaneError("the qualified final image digest must be distinct from task artifacts")

    tool_versions = _qualified_tool_versions(
        artifact_digests["qualifiedToolVersions"],
        required=spec["requiredQualifiedTools"],
    )
    tool_versions["image-build-manifest-sha256"] = build_manifest_digest
    tool_versions["image-build-receipt-sha256"] = build_receipt_digest
    tool_versions["image-artifact-inspection-receipt-sha256"] = inspection_receipt_digest
    tool_versions["image-qualification-result-sha256"] = qualification_result_digest
    tool_versions["project-content-sha256"] = project_digest
    tool_versions["source-content-sha256"] = source_content_digest

    brief_path = resolve_within(repo_root, spec["brief"], "Tier-1 public brief")
    task = {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": spec["taskId"],
        "family": family,
        "tier": "tier1",
        "taskKind": task_kind,
        "source": {
            "upstreamRepository": "https://github.com/JarodFroneman/jstack",
            "upstreamCommit": commit,
            "sourceArchiveSha256": source_archive_digest,
            "licenseSpdx": "MIT",
            "redistribution": "allowed",
        },
        "environment": {
            "isolation": "microvm",
            "imageReference": final_reference,
            "imageDigest": final_digest,
            "toolVersions": tool_versions,
            "network": "disabled-default",
        },
        "brief": {"path": spec["brief"], "sha256": file_digest(brief_path)},
        "baseline": {"commit": commit, "testResultSha256": baseline_digest},
        "changeBoundary": {
            "allowedPaths": copy.deepcopy(spec["allowed"]),
            "forbiddenPaths": ["proof-holdout", "hidden-tests", ".git"],
            "maxChangedFiles": spec["maxFiles"],
        },
        "budgets": {"wallClockSeconds": 1800, "tokenLimit": 100000, "costUsd": 1000.0},
        "holdout": {
            "hiddenTestBundleSha256": holdout_digest,
            "answerKeyAccess": "sealed-until-run-complete",
        },
        "invariants": copy.deepcopy(spec["invariants"]),
        "expectedOutcome": "fixed" if task_kind == "seeded-defect" else "safely-refused",
    }
    return validate_task(task)


def tier1_tasks(
    *,
    repo_root: Path,
    qualification_artifacts: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Create all 12 Tier-1 tasks with consistent content-addressed images.

    Multiple tasks may intentionally share one qualified toolchain image.  A
    repeated image digest must, however, carry byte-identical tool/build/
    qualification bindings; contradictory metadata for the same OCI content
    fails closed.
    """

    if not isinstance(qualification_artifacts, Mapping):
        raise ProofPlaneError("Tier-1 qualification set must be an object")
    expected_ids = [
        TIER1_PROJECTS[family][task_kind]["taskId"]
        for family in TARGET_FAMILIES
        for task_kind in ("seeded-defect", "clean-control")
    ]
    exact_fields(qualification_artifacts, expected_ids, "Tier-1 qualification set")
    tasks = []
    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            task_id = TIER1_PROJECTS[family][task_kind]["taskId"]
            artifacts = qualification_artifacts[task_id]
            if not isinstance(artifacts, Mapping):
                raise ProofPlaneError("Tier-1 qualification artifacts for %s must be an object" % task_id)
            tasks.append(
                tier1_task(
                    family,
                    task_kind,
                    repo_root=repo_root,
                    artifact_digests=artifacts,
                )
            )
    image_bindings: dict[str, str] = {}
    for task in tasks:
        environment = task["environment"]
        digest = environment["imageDigest"]
        binding = canonical_digest(
            {
                name: value
                for name, value in environment["toolVersions"].items()
                if name not in {"project-content-sha256", "source-content-sha256"}
            }
        )
        if digest in image_bindings and image_bindings[digest] != binding:
            raise ProofPlaneError(
                "a shared qualified final image cannot carry conflicting tool/build/qualification bindings"
            )
        image_bindings[digest] = binding
    return tasks


def historical_task(family: str, *, repo_root: Path, artifact_digests: Mapping[str, Any]) -> dict[str, Any]:
    if family not in HISTORICAL_REPLAYS:
        raise ProofPlaneError("unknown historical replay family %r" % family)
    spec = copy.deepcopy(HISTORICAL_REPLAYS[family])
    exact_fields(
        artifact_digests,
        (
            "sourceArchiveSha256",
            "sourceContentSha256",
            "baselineResultSha256",
            "hiddenTestBundleSha256",
            "finalImageReference",
            "finalImageDigest",
            "qualifiedToolVersions",
            "imageBuildManifestSha256",
            "imageBuildReceiptSha256",
            "imageArtifactInspectionReceiptSha256",
            "imageQualificationResultSha256",
        ),
        "historical task qualification artifacts",
    )
    source_archive_digest = _artifact_digest(
        artifact_digests["sourceArchiveSha256"], "sourceArchiveSha256"
    )
    if source_archive_digest != spec["source"]["sourceArchiveSha256"]:
        raise ProofPlaneError("sourceArchiveSha256 does not match the reviewed upstream archive")
    source_content_digest = _reviewed_artifact_digest(
        artifact_digests["sourceContentSha256"], "sourceContentSha256"
    )
    baseline_digest = _reviewed_artifact_digest(
        artifact_digests["baselineResultSha256"], "baselineResultSha256"
    )
    holdout_digest = _reviewed_artifact_digest(
        artifact_digests["hiddenTestBundleSha256"], "hiddenTestBundleSha256"
    )
    build_manifest_digest = _reviewed_artifact_digest(
        artifact_digests["imageBuildManifestSha256"], "imageBuildManifestSha256"
    )
    build_receipt_digest = _reviewed_artifact_digest(
        artifact_digests["imageBuildReceiptSha256"], "imageBuildReceiptSha256"
    )
    inspection_receipt_digest = _reviewed_artifact_digest(
        artifact_digests["imageArtifactInspectionReceiptSha256"],
        "imageArtifactInspectionReceiptSha256",
    )
    qualification_result_digest = _reviewed_artifact_digest(
        artifact_digests["imageQualificationResultSha256"], "imageQualificationResultSha256"
    )
    final_reference = artifact_digests["finalImageReference"]
    if not isinstance(final_reference, str):
        raise ProofPlaneError("finalImageReference must be a digest-qualified OCI reference")
    final_digest = _reviewed_artifact_digest(
        artifact_digests["finalImageDigest"], "finalImageDigest"
    )
    if _image_digest(final_reference) != final_digest:
        raise ProofPlaneError("finalImageReference and finalImageDigest do not match")
    if final_reference == spec["baseImageReference"] or final_digest == _image_digest(spec["baseImageReference"]):
        raise ProofPlaneError("an upstream base image is not a qualified runnable task image")
    tool_versions = _qualified_tool_versions(
        artifact_digests["qualifiedToolVersions"],
        required=spec["requiredQualifiedTools"],
    )
    # The v1 task contract has no separate image-build field.  Binding the
    # build/inspection receipt digests into toolVersions makes them part of
    # both the task digest and every expected run's environment digest without
    # weakening the closed schema.
    tool_versions["image-build-manifest-sha256"] = build_manifest_digest
    tool_versions["image-build-receipt-sha256"] = build_receipt_digest
    tool_versions["image-artifact-inspection-receipt-sha256"] = inspection_receipt_digest
    tool_versions["image-qualification-result-sha256"] = qualification_result_digest
    tool_versions["source-content-sha256"] = source_content_digest
    task = {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": spec["taskId"],
        "family": family,
        "tier": "tier2",
        "taskKind": "historical-replay",
        "source": spec["source"],
        "environment": {
            "isolation": "microvm",
            "imageReference": final_reference,
            "imageDigest": final_digest,
            "toolVersions": tool_versions,
            "network": "disabled-default",
        },
        "brief": {
            "path": spec["brief"],
            "sha256": file_digest(repo_root / spec["brief"]),
        },
        "baseline": {
            "commit": spec["source"]["upstreamCommit"],
            "testResultSha256": baseline_digest,
        },
        "changeBoundary": {
            "allowedPaths": spec["allowed"],
            "forbiddenPaths": spec["forbidden"],
            "maxChangedFiles": spec["maxFiles"],
        },
        "budgets": {"wallClockSeconds": 1800, "tokenLimit": 100000, "costUsd": 1000.0},
        "holdout": {
            "hiddenTestBundleSha256": holdout_digest,
            "answerKeyAccess": "sealed-until-run-complete",
        },
        "invariants": spec["invariants"],
        "expectedOutcome": "fixed",
    }
    return validate_task(task)


def inventory() -> dict[str, Any]:
    expected_tier1_shapes = {
        (family, task_kind)
        for family in TARGET_FAMILIES
        for task_kind in ("seeded-defect", "clean-control")
    }
    actual_tier1_shapes = {
        (family, task_kind)
        for family, projects in TIER1_PROJECTS.items()
        for task_kind in projects
    }
    if actual_tier1_shapes != expected_tier1_shapes:
        raise ProofPlaneError("Tier-1 inventory must cover six families and two reviewed task kinds")
    tier1_task_ids = [
        TIER1_PROJECTS[family][task_kind]["taskId"]
        for family in TARGET_FAMILIES
        for task_kind in ("seeded-defect", "clean-control")
    ]
    if len(set(tier1_task_ids)) != 12:
        raise ProofPlaneError("Tier-1 task identifiers must be unique")
    historical_task_ids = [HISTORICAL_REPLAYS[family]["taskId"] for family in TARGET_FAMILIES]
    return {
        "families": list(TARGET_FAMILIES),
        "taskKinds": list(TASK_KINDS),
        "designedTaskCount": 18,
        "designedTaskIds": tier1_task_ids + historical_task_ids,
        "tier1ProjectCount": len(tier1_task_ids),
        "tier1TaskIds": tier1_task_ids,
        "historicalReplayCount": len(HISTORICAL_REPLAYS),
        "historicalTaskIds": historical_task_ids,
        "historicalBaseImages": [
            {
                "family": family,
                "baseImageReference": HISTORICAL_REPLAYS[family]["baseImageReference"],
                "purpose": "build-input-only-not-runnable",
            }
            for family in TARGET_FAMILIES
        ],
        "runnableDescriptorsReady": False,
        "seededAndCleanStatus": (
            "blocked-pending-content-addressed-source-archives-baselines-holdouts-"
            "and-qualified-content-addressed-images"
        ),
    }


__all__ = [
    "COMMON_QUALIFIED_TOOLS",
    "HISTORICAL_REPLAYS",
    "TIER1_PROJECTS",
    "historical_task",
    "inventory",
    "tier1_project_content_digest",
    "tier1_task",
    "tier1_tasks",
]
