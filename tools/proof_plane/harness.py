"""Deterministic lock for every executable Beta.1 study-harness input.

The lock deliberately excludes itself to avoid a digest cycle.  Its raw file
digest is instead bound by the immutable study registration.  The accepted
path set is derived from closed repository locations, so a registration cannot
silently omit a validator, scorer, protocol, or schema from preregistration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .common import ProofPlaneError, exact_fields, file_digest, relative_path, resolve_within


HARNESS_LOCK_SCHEMA = "jstack.eval.proof-harness-lock.v1"
HARNESS_LOCK_PATH = "evals/protocols/proof-harness-lock.v1.json"
HARNESS_DIGEST_ALGORITHM = "sha256-raw-bytes-v1"
_PREREGISTRATION_OUTPUT_PATHS = {
    "evals/protocols/proof-beta1-study-registration.v1.json",
    "evals/protocols/proof-evidence-bindings.v1.json",
    "evals/protocols/proof-execution-schedule.v1.json",
}


def _expected_harness_paths(repo_root: Path) -> tuple[str, ...]:
    """Return the complete closed file set that can affect study outcomes."""

    root = repo_root.resolve()
    proof_root = root / "tools" / "proof_plane"
    runner_root = root / "evals" / "runner"
    schema_root = root / "evals" / "schemas"
    protocol_root = root / "evals" / "protocols"
    locations = (
        (proof_root, {".py", ".c"}),
        (runner_root, {".py"}),
        (schema_root, {".json"}),
        (protocol_root, {".json", ".md", ".toml"}),
    )
    package_initializer = root / "evals" / "__init__.py"
    if package_initializer.is_symlink() or not package_initializer.is_file():
        raise ProofPlaneError("evals package initializer must be a regular, non-symlink file")
    paths: list[str] = ["evals/__init__.py"]
    for directory, suffixes in locations:
        if directory.is_symlink() or not directory.is_dir():
            raise ProofPlaneError("proof harness source directory is missing or is a symlink: %s" % directory)
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = path.relative_to(root).as_posix()
            # These canonical documents are outputs of preregistration and
            # are independently bound by the registration/bundle.  Including
            # them here would create a digest cycle through the registration's
            # harnessLockSha256 field.
            if relative == HARNESS_LOCK_PATH or relative in _PREREGISTRATION_OUTPUT_PATHS:
                continue
            if path.suffix not in suffixes:
                continue
            if path.is_symlink() or not path.is_file():
                raise ProofPlaneError("proof harness member must be a regular, non-symlink file: %s" % relative)
            paths.append(relative)
    required = {
        "evals/__init__.py",
        "evals/runner/__init__.py",
        "evals/runner/cli.py",
        "evals/runner/contracts.py",
        "evals/runner/mock.py",
        "evals/runner/score.py",
        "evals/schemas/corpus-manifest.v1.schema.json",
        "evals/schemas/human-review.v1.schema.json",
        "evals/schemas/run-envelope.v1.schema.json",
        "evals/schemas/score.v1.schema.json",
        "evals/schemas/task.v1.schema.json",
        "evals/protocols/codex-study.config.toml",
        "evals/protocols/isolation-policy.v1.md",
        "evals/protocols/jstack.v1.md",
        "evals/protocols/plain.v1.md",
        "evals/protocols/review-rubric.v1.md",
        "tools/proof_plane/__init__.py",
        "tools/proof_plane/common.py",
        "tools/proof_plane/study.py",
        "tools/proof_plane/runner.py",
        "tools/proof_plane/broker.py",
        "tools/proof_plane/evidence.py",
        "tools/proof_plane/executor.py",
        "tools/proof_plane/grading.py",
        "tools/proof_plane/harness.py",
        "tools/proof_plane/review.py",
        "tools/proof_plane/signatures.py",
        "tools/proof_plane/task_specs.py",
        "tools/proof_plane/verification.py",
    }
    missing = sorted(required - set(paths))
    if missing:
        raise ProofPlaneError("proof harness required files are missing: %s" % ", ".join(missing))
    if len(paths) != len(set(paths)):
        raise ProofPlaneError("proof harness path discovery produced duplicates")
    return tuple(sorted(paths))


def build_harness_lock(repo_root: Path) -> dict[str, Any]:
    """Build the deterministic lock document; writing is a separate review step."""

    paths = _expected_harness_paths(repo_root)
    return {
        "schemaVersion": HARNESS_LOCK_SCHEMA,
        "digestAlgorithm": HARNESS_DIGEST_ALGORITHM,
        "selfExcludedPath": HARNESS_LOCK_PATH,
        "files": [
            {"path": relative, "sha256": file_digest(resolve_within(repo_root, relative, "harness path"))}
            for relative in paths
        ],
    }


def validate_harness_lock(value: Mapping[str, Any], *, repo_root: Path) -> dict[str, Any]:
    """Re-hash a lock and require the exact complete harness path set."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("proof harness lock must be an object")
    exact_fields(
        value,
        ("schemaVersion", "digestAlgorithm", "selfExcludedPath", "files"),
        "proof harness lock",
    )
    if value["schemaVersion"] != HARNESS_LOCK_SCHEMA:
        raise ProofPlaneError("unsupported proof harness lock schemaVersion")
    if value["digestAlgorithm"] != HARNESS_DIGEST_ALGORITHM:
        raise ProofPlaneError("unsupported proof harness digest algorithm")
    if value["selfExcludedPath"] != HARNESS_LOCK_PATH:
        raise ProofPlaneError("proof harness lock must exclude only its fixed self path")
    files = value["files"]
    if not isinstance(files, list):
        raise ProofPlaneError("proof harness lock files must be an array")
    expected_paths = _expected_harness_paths(repo_root)
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("proof harness lock entry %d must be an object" % index)
        exact_fields(item, ("path", "sha256"), "proof harness lock entry %d" % index)
        relative = relative_path(item["path"], "proof harness lock entry path")
        if relative == HARNESS_LOCK_PATH:
            raise ProofPlaneError("proof harness lock must not include itself")
        if relative in seen:
            raise ProofPlaneError("proof harness lock contains a duplicate path")
        seen.add(relative)
        digest = item["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ProofPlaneError("proof harness lock digest must be lowercase SHA-256")
        path = resolve_within(repo_root, relative, "proof harness lock entry")
        if file_digest(path) != digest:
            raise ProofPlaneError("proof harness member digest mismatch: %s" % relative)
        normalized.append({"path": relative, "sha256": digest})
    observed_paths = tuple(item["path"] for item in normalized)
    if observed_paths != tuple(sorted(observed_paths)):
        raise ProofPlaneError("proof harness lock files must use deterministic path ordering")
    if observed_paths != expected_paths:
        missing = sorted(set(expected_paths) - set(observed_paths))
        extra = sorted(set(observed_paths) - set(expected_paths))
        details = []
        if missing:
            details.append("missing %s" % ", ".join(missing))
        if extra:
            details.append("unknown %s" % ", ".join(extra))
        raise ProofPlaneError("proof harness lock path set is not complete: %s" % "; ".join(details))
    return {
        "schemaVersion": HARNESS_LOCK_SCHEMA,
        "digestAlgorithm": HARNESS_DIGEST_ALGORITHM,
        "selfExcludedPath": HARNESS_LOCK_PATH,
        "files": normalized,
    }


__all__ = [
    "HARNESS_DIGEST_ALGORITHM",
    "HARNESS_LOCK_PATH",
    "HARNESS_LOCK_SCHEMA",
    "build_harness_lock",
    "validate_harness_lock",
]
