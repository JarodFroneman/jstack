"""Private, Git-bound project intelligence with a closed Graphify provider.

JStack owns policy, storage, receipts, evidence strength, and workflow routing.
Graphify is an isolated subprocess used only for local AST extraction and its
native static HTML export. Nothing in this module installs assistant skills,
hooks, listeners, hosted services, or repository instructions.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


PROJECT_INTELLIGENCE_SCHEMA_VERSION = "jstack.project-intelligence.v1"
SNAPSHOT_SCHEMA_VERSION = "jstack.project-intelligence-snapshot.v1"
APPLICABILITY_SCHEMA_VERSION = "jstack.project-intelligence-applicability.v1"
PROVIDER_STATUS_SCHEMA_VERSION = "jstack.project-intelligence-provider-status.v1"
QUERY_SCHEMA_VERSION = "jstack.project-intelligence-query.v1"
IMPACT_SCHEMA_VERSION = "jstack.project-intelligence-impact.v1"

MAX_GRAPH_BYTES = 100_000_000
MAX_HTML_BYTES = 150_000_000
MAX_PROVIDER_OUTPUT_BYTES = 2_000_000
MAX_NODES = 500_000
MAX_EDGES = 2_000_000
MAX_QUERY_NODES = 500
MAX_QUERY_EDGES = 1_000
MAX_QUERY_DEPTH = 5
DEFAULT_HTML_NODE_LIMIT = 5_000
PROVIDER_TIMEOUT_SECONDS = 600
MAX_RETAINED_SNAPSHOTS = 8
MAX_RETAINED_QUERIES = 32

CONFIDENCE_LEVELS = ("EXTRACTED", "INFERRED", "AMBIGUOUS")
MANDATORY_WORKFLOWS = {
    "jstack-audit",
    "jstack-full-team",
    "jstack-loop",
    "jstack-subagents",
}
MATERIAL_TERMS = {
    "architecture",
    "authentication",
    "authorization",
    "cross-module",
    "database",
    "dependency",
    "dependencies",
    "distributed",
    "encryption",
    "enterprise",
    "migration",
    "multi-module",
    "payment",
    "permissions",
    "production",
    "rbac",
    "refactor",
    "release",
    "schema",
    "security",
    "upgrade",
}
TRIVIAL_TERMS = {
    "comment",
    "copy edit",
    "formatting",
    "spelling",
    "typo",
    "whitespace",
}
CODE_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cxx",
    ".elixir",
    ".ex",
    ".exs",
    ".f90",
    ".for",
    ".go",
    ".groovy",
    ".h",
    ".hpp",
    ".java",
    ".jl",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".lua",
    ".m",
    ".mm",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
    ".v",
    ".zig",
}
GRAPH_COVERAGE_EXTENSIONS = CODE_EXTENSIONS - {".json"}

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_LOCATION_RE = re.compile(r"^L?[1-9][0-9]*(?::[1-9][0-9]*)?$")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.:/-]*")


class ProjectIntelligenceError(ValueError):
    """The provider, graph, storage, or evidence contract is invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _catalog_path() -> Path:
    return Path(__file__).with_name("catalog.v1.json")


def provider_catalog() -> dict[str, Any]:
    try:
        value = json.loads(_catalog_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectIntelligenceError("The project-intelligence provider catalog is unavailable.") from exc
    required = {
        "schemaVersion",
        "providerId",
        "displayName",
        "packageName",
        "version",
        "sourceRepository",
        "sourceBranch",
        "sourceCommit",
        "license",
        "distribution",
        "runtime",
        "execution",
        "confidencePolicy",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ProjectIntelligenceError("The project-intelligence provider catalog has drifted.")
    if value["packageName"] != "graphifyy" or value["providerId"] != "graphify-local-ast":
        raise ProjectIntelligenceError("The project-intelligence provider identity is unsupported.")
    if not _GIT_SHA_RE.fullmatch(str(value["sourceCommit"])):
        raise ProjectIntelligenceError("The provider source commit is not pinned.")
    distribution = value["distribution"]
    if not isinstance(distribution, dict) or set(distribution) != {"filename", "sha256", "url"}:
        raise ProjectIntelligenceError("The provider distribution contract has drifted.")
    if not _DIGEST_RE.fullmatch(str(distribution["sha256"])):
        raise ProjectIntelligenceError("The provider distribution digest is invalid.")
    runtime = value["runtime"]
    if (
        not isinstance(runtime, dict)
        or set(runtime)
        != {
            "relativeRoot",
            "posixEntrypoint",
            "windowsEntrypoint",
            "launcherArguments",
            "pythonRequirement",
            "installMode",
        }
        or runtime["posixEntrypoint"] != "venv/bin/python"
        or runtime["windowsEntrypoint"] != "venv/Scripts/python.exe"
        or runtime["launcherArguments"] != ["-m", "graphify"]
        or runtime["installMode"] != "isolated-managed-venv"
    ):
        raise ProjectIntelligenceError("The provider runtime contract has drifted.")
    return value


def catalog_digest() -> str:
    return canonical_digest(provider_catalog())


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: Path, *, maximum: int) -> tuple[int, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProjectIntelligenceError(f"Required private artifact is unavailable: {path.name}.") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProjectIntelligenceError(f"Private artifact is not a single-link regular file: {path.name}.")
    if metadata.st_size > maximum:
        raise ProjectIntelligenceError(f"Private artifact exceeds its {maximum}-byte safety limit: {path.name}.")
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise ProjectIntelligenceError(
                        f"Private artifact grew beyond its {maximum}-byte safety limit: {path.name}."
                    )
                digest.update(chunk)
    except OSError as exc:
        raise ProjectIntelligenceError(f"Private artifact could not be read: {path.name}.") from exc
    after = path.lstat()
    stable = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(metadata, field) != getattr(after, field) for field in stable):
        raise ProjectIntelligenceError(f"Private artifact changed while it was read: {path.name}.")
    return total, digest.hexdigest()


def _ensure_private_directory(path: Path, *, home: Path) -> Path:
    home = home.expanduser().resolve()
    try:
        relative = path.expanduser().relative_to(home)
    except ValueError as exc:
        raise ProjectIntelligenceError("Project-intelligence state must remain below the user home.") from exc
    current = home
    for index, component in enumerate(relative.parts):
        current = current / component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ProjectIntelligenceError("Private project-intelligence storage could not be created.") from exc
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ProjectIntelligenceError("Private project-intelligence storage contains a linked or non-directory component.")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ProjectIntelligenceError("Private project-intelligence storage is not current-user owned.")
        if index >= 1 and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ProjectIntelligenceError("Project-intelligence directories below ~/.jstack must use private mode 0700.")
    return path


def repository_id(project_path: Path) -> str:
    return hashlib.sha256(str(project_path.resolve()).encode("utf-8")).hexdigest()


def project_storage_root(project_path: Path, *, home: Path | None = None) -> Path:
    actual_home = (home or Path.home()).expanduser().resolve()
    root = actual_home / ".jstack" / "project-intelligence" / repository_id(project_path)
    return _ensure_private_directory(root, home=actual_home)


def managed_runtime_root(*, home: Path | None = None) -> Path:
    catalog = provider_catalog()
    actual_home = (home or Path.home()).expanduser().resolve()
    relative = Path(catalog["runtime"]["relativeRoot"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ProjectIntelligenceError("The managed provider runtime path is unsafe.")
    return actual_home / relative


def managed_executable(*, home: Path | None = None) -> Path:
    catalog = provider_catalog()
    entry = (
        catalog["runtime"]["windowsEntrypoint"]
        if os.name == "nt"
        else catalog["runtime"]["posixEntrypoint"]
    )
    return managed_runtime_root(home=home) / entry


def _provider_environment(*, graph_out: Path, runtime_home: Path, executable: Path) -> dict[str, str]:
    path_entries = [str(executable.parent)]
    for candidate in (Path("/usr/bin"), Path("/bin"), Path("/usr/local/bin"), Path("/opt/homebrew/bin")):
        if candidate.is_dir():
            path_entries.append(str(candidate))
    return {
        "CI": "1",
        "GRAPHIFY_NO_TIPS": "1",
        "GRAPHIFY_OUT": str(graph_out),
        "HOME": str(runtime_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(path_entries),
        "PYTHONNOUSERSITE": "1",
        "USERPROFILE": str(runtime_home),
        "XDG_CACHE_HOME": str(runtime_home / ".cache"),
        "XDG_CONFIG_HOME": str(runtime_home / ".config"),
    }


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def _run_provider(
    executable: Path,
    args: Sequence[str],
    *,
    cwd: Path,
    graph_out: Path,
    runtime_home: Path,
    timeout: int = PROVIDER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    env = _provider_environment(
        graph_out=graph_out,
        runtime_home=runtime_home,
        executable=executable,
    )
    launcher_arguments = provider_catalog()["runtime"]["launcherArguments"]
    command = [str(executable), *launcher_arguments, *args]
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name != "nt"),
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt"
                else 0
            ),
        )
    except OSError as exc:
        raise ProjectIntelligenceError("The managed Graphify process could not be started.") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate(process)
        stdout, stderr = process.communicate()
        raise ProjectIntelligenceError(f"The managed Graphify process exceeded the {timeout}-second timeout.") from exc
    if len(stdout) + len(stderr) > MAX_PROVIDER_OUTPUT_BYTES:
        raise ProjectIntelligenceError("The managed Graphify process exceeded the output safety limit.")
    result = {
        "ok": process.returncode == 0,
        "returncode": process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "args": list(args),
    }
    if not result["ok"]:
        detail = (result["stderr"] or result["stdout"]).strip()[-2000:]
        raise ProjectIntelligenceError(
            f"The managed Graphify process failed with exit {process.returncode}: {detail or 'no diagnostic output'}"
        )
    return result


def discover_provider(*, home: Path | None = None, executable: Path | None = None) -> dict[str, Any]:
    catalog = provider_catalog()
    candidate = (executable or managed_executable(home=home)).expanduser()
    status = {
        "schemaVersion": PROVIDER_STATUS_SCHEMA_VERSION,
        "providerId": catalog["providerId"],
        "expectedVersion": catalog["version"],
        "catalogDigest": catalog_digest(),
        "managedPath": str(candidate),
        "status": "unavailable",
        "version": None,
        "reason": "managed-runtime-missing",
        "executionProfile": catalog["execution"]["isolationDisclosure"],
    }
    try:
        metadata = candidate.lstat()
    except OSError:
        return status
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return {**status, "status": "error", "reason": "managed-entrypoint-not-regular"}
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        return {**status, "status": "error", "reason": "managed-entrypoint-owner-mismatch"}
    try:
        result = _run_provider(
            candidate,
            ["--version"],
            cwd=candidate.parent,
            graph_out=candidate.parent / ".version-check-out",
            runtime_home=candidate.parent / ".version-check-home",
            timeout=20,
        )
    except ProjectIntelligenceError as exc:
        return {**status, "status": "error", "reason": "version-check-failed", "diagnostic": str(exc)}
    match = re.fullmatch(r"graphify\s+([0-9]+(?:\.[0-9]+){2})\s*", result["stdout"])
    if not match:
        return {**status, "status": "error", "reason": "version-output-invalid"}
    version = match.group(1)
    if version != catalog["version"]:
        return {**status, "status": "error", "version": version, "reason": "version-mismatch"}
    return {**status, "status": "available", "version": version, "reason": "pinned-runtime-ready"}


def _relative_source(value: Any, project_path: Path) -> str | None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    raw = Path(value.strip())
    if raw.is_absolute():
        try:
            raw = raw.resolve(strict=False).relative_to(project_path.resolve())
        except ValueError:
            return None
    parts = raw.as_posix().split("/")
    if any(part in {"", ".", ".."} for part in parts) or parts[0].lower() == ".git":
        return None
    candidate = (project_path / raw).resolve(strict=False)
    try:
        candidate.relative_to(project_path.resolve())
    except ValueError:
        return None
    return raw.as_posix()


def _source_location(value: Any) -> str | None:
    if isinstance(value, int) and value > 0:
        return f"L{value}"
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not _SOURCE_LOCATION_RE.fullmatch(normalized):
        return None
    return normalized if normalized.startswith("L") else f"L{normalized}"


def _load_graph(path: Path, project_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    size, digest = _sha256_file(path, maximum=MAX_GRAPH_BYTES)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectIntelligenceError("Graphify graph.json is not valid bounded UTF-8 JSON.") from exc
    if not isinstance(raw, dict):
        raise ProjectIntelligenceError("Graphify graph.json must be an object.")
    nodes = raw.get("nodes")
    edges = raw.get("edges", raw.get("links"))
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ProjectIntelligenceError("Graphify graph.json must contain node and edge arrays.")
    if len(nodes) > MAX_NODES or len(edges) > MAX_EDGES:
        raise ProjectIntelligenceError("Graphify graph.json exceeds JStack's node or edge safety limit.")

    node_ids: set[str] = set()
    node_anchors: dict[str, tuple[str | None, str | None]] = {}
    normalized_nodes: list[dict[str, Any]] = []
    anchored_nodes = 0
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ProjectIntelligenceError(f"Graphify node {index} is not an object.")
        node_id = str(node.get("id") or "").strip()
        label = str(node.get("label") or "").strip()
        if not node_id or len(node_id) > 2000 or not label or len(label) > 2000:
            raise ProjectIntelligenceError(f"Graphify node {index} has an invalid id or label.")
        if node_id in node_ids:
            raise ProjectIntelligenceError(f"Graphify graph contains a duplicate node id: {node_id[:100]}.")
        node_ids.add(node_id)
        source_file = _relative_source(node.get("source_file"), project_path)
        source_location = _source_location(node.get("source_location"))
        if source_file and source_location:
            anchored_nodes += 1
        node_anchors[node_id] = (source_file, source_location)
        normalized_nodes.append(
            {
                "id": node_id,
                "label": label,
                "type": str(node.get("type") or "unknown")[:100],
                "sourceFile": source_file,
                "sourceLocation": source_location,
            }
        )

    # Graphify intentionally leaves some import and reference targets outside
    # its node array. Preserve those relationships as bounded, unanchored
    # reference nodes instead of treating valid provider output as corruption.
    unresolved_targets: set[str] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise ProjectIntelligenceError(
                f"Graphify edge {index} is not an object."
            )
        source_value = edge.get("source")
        target_value = edge.get("target")
        relation_value = edge.get("relation", edge.get("type"))
        if not isinstance(source_value, str) or not isinstance(target_value, str):
            raise ProjectIntelligenceError(
                f"Graphify edge {index} has invalid endpoints or relation."
            )
        source = source_value.strip()
        target = target_value.strip()
        relation = str(relation_value or "").strip()
        if (
            not source
            or len(source) > 2000
            or source not in node_ids
            or not target
            or len(target) > 2000
            or not relation
            or len(relation) > 200
        ):
            raise ProjectIntelligenceError(
                f"Graphify edge {index} has invalid endpoints or relation."
            )
        if target not in node_ids:
            unresolved_targets.add(target)
    if len(node_ids) + len(unresolved_targets) > MAX_NODES:
        raise ProjectIntelligenceError(
            "Graphify graph exceeds JStack's node safety limit after resolving edge targets."
        )
    for target in sorted(unresolved_targets):
        node_ids.add(target)
        node_anchors[target] = (None, None)
        normalized_nodes.append(
            {
                "id": target,
                "label": target,
                "type": "unresolved-reference",
                "sourceFile": None,
                "sourceLocation": None,
            }
        )

    confidence_counts = {level: 0 for level in CONFIDENCE_LEVELS}
    confidence_counts["UNKNOWN"] = 0
    strong_edges = 0
    normalized_edges: list[dict[str, Any]] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise ProjectIntelligenceError(f"Graphify edge {index} is not an object.")
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        relation = str(edge.get("relation", edge.get("type")) or "").strip()
        if source not in node_ids or target not in node_ids or not relation or len(relation) > 200:
            raise ProjectIntelligenceError(f"Graphify edge {index} has invalid endpoints or relation.")
        confidence = str(edge.get("confidence") or "UNKNOWN").strip().upper()
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "UNKNOWN"
        confidence_counts[confidence] += 1
        source_file = _relative_source(edge.get("source_file"), project_path)
        source_location = _source_location(edge.get("source_location"))
        if not (source_file and source_location):
            endpoint_file, endpoint_location = node_anchors.get(source, (None, None))
            source_file = source_file or endpoint_file
            source_location = source_location or endpoint_location
        strong = confidence == "EXTRACTED" and bool(source_file and source_location)
        if strong:
            strong_edges += 1
        normalized_edges.append(
            {
                "id": hashlib.sha256(
                    f"{source}\0{target}\0{relation}\0{index}".encode("utf-8")
                ).hexdigest(),
                "source": source,
                "target": target,
                "relation": relation,
                "confidence": confidence,
                "sourceFile": source_file,
                "sourceLocation": source_location,
                "strongEvidence": strong,
            }
        )

    normalized = {"nodes": normalized_nodes, "edges": normalized_edges}
    summary = {
        "sha256": digest,
        "bytes": size,
        "nodeCount": len(normalized_nodes),
        "edgeCount": len(normalized_edges),
        "anchoredNodeCount": anchored_nodes,
        "strongEvidenceEdgeCount": strong_edges,
        "confidenceCounts": confidence_counts,
        "normalizedDigest": canonical_digest(normalized),
    }
    return normalized, summary


def _binding(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "gitRoot",
        "gitHead",
        "gitTree",
        "projectFingerprint",
        "policyDigest",
        "clean",
    }
    if not required.issubset(value):
        raise ProjectIntelligenceError("The project binding is incomplete.")
    git_root = str(value["gitRoot"])
    git_head = str(value["gitHead"])
    git_tree = str(value["gitTree"])
    fingerprint = str(value["projectFingerprint"])
    policy_digest = str(value["policyDigest"])
    if not _GIT_SHA_RE.fullmatch(git_head) or not _GIT_SHA_RE.fullmatch(git_tree):
        raise ProjectIntelligenceError("The project binding requires exact Git commit and tree identities.")
    if not _DIGEST_RE.fullmatch(fingerprint):
        raise ProjectIntelligenceError("The project binding requires an exact project fingerprint.")
    if not _DIGEST_RE.fullmatch(policy_digest):
        raise ProjectIntelligenceError("The project binding requires an exact JStack policy digest.")
    return {
        "gitRoot": git_root,
        "gitHead": git_head,
        "gitTree": git_tree,
        "projectFingerprint": fingerprint,
        "policyDigest": policy_digest,
        "clean": bool(value["clean"]),
    }


def supported_source_count(project_path: Path, files: Iterable[str] | None = None) -> int:
    if files is not None:
        return sum(1 for item in files if Path(item).suffix.lower() in CODE_EXTENSIONS)
    count = 0
    for path in project_path.rglob("*"):
        if count >= 1:
            break
        try:
            relative = path.relative_to(project_path)
        except ValueError:
            continue
        if any(part in {".git", "node_modules", "vendor", ".venv", "venv"} for part in relative.parts):
            continue
        if path.is_file() and not path.is_symlink() and path.suffix.lower() in CODE_EXTENSIONS:
            count += 1
    return count


def is_supported_source_path(path: str) -> bool:
    return Path(str(path)).suffix.lower() in CODE_EXTENSIONS


def requires_graph_source_coverage(path: str) -> bool:
    """Return whether Graphify is expected to emit AST inventory for a path."""
    return Path(str(path)).suffix.lower() in GRAPH_COVERAGE_EXTENSIONS


def graph_inventory(project_path: Path, graph_path: Path) -> dict[str, Any]:
    normalized, summary = _load_graph(graph_path, project_path.resolve())
    source_files = sorted(
        {
            str(node["sourceFile"])
            for node in normalized["nodes"]
            if node.get("sourceFile")
        }
        | {
            str(edge["sourceFile"])
            for edge in normalized["edges"]
            if edge.get("sourceFile")
        }
    )
    return {
        "graphDigest": summary["sha256"],
        "sourceFiles": source_files,
        "strongEdgeIds": [
            edge["id"] for edge in normalized["edges"] if edge["strongEvidence"]
        ],
        "advisoryEdgeIds": [
            edge["id"] for edge in normalized["edges"] if not edge["strongEvidence"]
        ],
    }


def assess_applicability(
    *,
    goal: str,
    workflow_mode: str,
    changed_paths: Sequence[str] | None,
    supported_sources: int,
    mode: str = "auto",
) -> dict[str, Any]:
    normalized_mode = str(mode or "auto").strip().lower()
    if normalized_mode not in {"auto", "required", "off"}:
        raise ProjectIntelligenceError("Project-intelligence mode must be auto, required, or off.")
    normalized_goal = " ".join(str(goal or "").lower().split())
    paths = sorted({str(path).replace("\\", "/") for path in (changed_paths or [])})
    code_paths = [path for path in paths if Path(path).suffix.lower() in CODE_EXTENSIONS]
    mandatory_reasons: list[str] = []
    if workflow_mode in MANDATORY_WORKFLOWS:
        mandatory_reasons.append(f"workflow:{workflow_mode}")
    matched_material = sorted(term for term in MATERIAL_TERMS if term in normalized_goal)
    if matched_material:
        mandatory_reasons.append("material-goal:" + ",".join(matched_material))
    if len(code_paths) >= 4:
        mandatory_reasons.append("cross-module-change")
    if normalized_mode == "required":
        mandatory_reasons.append("explicit-required-mode")
    trivial = bool(normalized_goal) and any(term in normalized_goal for term in TRIVIAL_TERMS)
    trivial = trivial and len(code_paths) <= 1 and not matched_material

    if supported_sources == 0:
        state = "deferred" if not paths else "unsupported"
        reason = "greenfield-awaiting-first-code-scaffold" if not paths else "no-supported-source-language"
    elif mandatory_reasons:
        state = "required"
        reason = mandatory_reasons[0]
    elif normalized_mode == "off" and trivial:
        state = "skipped"
        reason = "explicit-off-for-trivial-change"
    elif normalized_mode == "off":
        state = "required"
        reason = "off-mode-rejected-for-non-trivial-work"
        mandatory_reasons.append(reason)
    elif trivial:
        state = "optional"
        reason = "trivial-change"
    elif code_paths or not paths:
        state = "required"
        reason = "material-code-work"
        mandatory_reasons.append(reason)
    else:
        state = "optional"
        reason = "non-code-work"
    return {
        "schemaVersion": APPLICABILITY_SCHEMA_VERSION,
        "mode": normalized_mode,
        "state": state,
        "reason": reason,
        "mandatoryReasons": mandatory_reasons,
        "workflowMode": workflow_mode,
        "supportedSourceCount": supported_sources,
        "changedPathCount": len(paths),
        "changedCodePathCount": len(code_paths),
        "visualizationRequired": state == "required",
        "failClosed": state == "required",
        "disclosureRequired": state in {"deferred", "optional", "skipped", "unsupported"},
    }


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(_canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _prune_private_directories(root: Path, *, keep: set[str], limit: int) -> None:
    """Bound private generated state without following links or touching repositories."""
    if not root.exists():
        return
    candidates: list[tuple[int, str, Path]] = []
    for child in root.iterdir():
        try:
            metadata = child.lstat()
        except OSError:
            continue
        if child.name in keep or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            continue
        candidates.append((metadata.st_mtime_ns, child.name, child))
    candidates.sort(reverse=True)
    for _, _, child in candidates[max(0, limit - len(keep)) :]:
        shutil.rmtree(child, ignore_errors=True)


def load_current_snapshot(
    project_path: Path,
    binding: Mapping[str, Any],
    *,
    home: Path | None = None,
) -> dict[str, Any] | None:
    """Return the current immutable snapshot only when every binding is exact."""
    project_path = project_path.resolve()
    exact_binding = _binding(binding)
    root = project_storage_root(project_path, home=home)
    pointer_path = root / "current.json"
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(pointer, dict):
        return None
    try:
        snapshot = load_snapshot(
            project_path,
            str(pointer.get("manifestRelativePath") or ""),
            expected_manifest_digest=str(pointer.get("manifestDigest") or ""),
            home=home,
        )
    except ProjectIntelligenceError:
        return None
    if snapshot["manifest"].get("binding") != exact_binding:
        return None
    return snapshot


def build_snapshot(
    project_path: Path,
    binding: Mapping[str, Any],
    *,
    home: Path | None = None,
    executable: Path | None = None,
    render: bool = True,
) -> dict[str, Any]:
    project_path = project_path.resolve()
    exact_binding = _binding(binding)
    if exact_binding["gitRoot"] != str(project_path):
        raise ProjectIntelligenceError("The project binding does not match the requested repository root.")
    provider = discover_provider(home=home, executable=executable)
    if provider["status"] != "available":
        raise ProjectIntelligenceError(
            f"The pinned managed Graphify runtime is not ready: {provider['reason']}."
        )
    actual_home = (home or Path.home()).expanduser().resolve()
    root = project_storage_root(project_path, home=actual_home)
    current = load_current_snapshot(
        project_path,
        exact_binding,
        home=actual_home,
    )
    if current is not None and (not render or current.get("visualizationPath")):
        return current
    staging_root = _ensure_private_directory(root / "staging", home=actual_home)
    snapshots_root = _ensure_private_directory(root / "snapshots", home=actual_home)
    stage = staging_root / uuid.uuid4().hex
    stage.mkdir(mode=0o700)
    runtime_home = stage / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    selected_executable = (executable or managed_executable(home=actual_home)).expanduser()
    catalog = provider_catalog()
    try:
        index_result = _run_provider(
            selected_executable,
            ["extract", str(project_path), "--no-cluster", "--code-only", "--timing"],
            cwd=project_path,
            graph_out=stage,
            runtime_home=runtime_home,
        )
        graph_path = stage / "graph.json"
        normalized, graph_summary = _load_graph(graph_path, project_path)
        html_artifact: dict[str, Any] | None = None
        if render:
            html_node_limit = max(
                DEFAULT_HTML_NODE_LIMIT,
                int(graph_summary["nodeCount"]),
            )
            _run_provider(
                selected_executable,
                [
                    "export",
                    "html",
                    "--graph",
                    str(graph_path),
                    "--node-limit",
                    str(html_node_limit),
                ],
                cwd=project_path,
                graph_out=stage,
                runtime_home=runtime_home,
            )
            html_path = stage / "graph.html"
            html_size, html_digest = _sha256_file(html_path, maximum=MAX_HTML_BYTES)
            html_artifact = {
                "relativePath": "graph.html",
                "sha256": html_digest,
                "bytes": html_size,
                "providerNative": True,
            }
        shutil.rmtree(runtime_home, ignore_errors=True)
        manifest_core = {
            "schemaVersion": SNAPSHOT_SCHEMA_VERSION,
            "generatedAt": _timestamp(),
            "repositoryId": repository_id(project_path),
            "binding": exact_binding,
            "provider": {
                "id": catalog["providerId"],
                "package": catalog["packageName"],
                "version": catalog["version"],
                "sourceCommit": catalog["sourceCommit"],
                "catalogDigest": catalog_digest(),
                "executionProfile": catalog["execution"]["isolationDisclosure"],
            },
            "graph": {"relativePath": "graph.json", **graph_summary},
            "visualization": html_artifact,
            "evidencePolicy": {
                "strong": "EXTRACTED-and-source-anchored",
                "advisory": ["INFERRED", "AMBIGUOUS", "unanchored-EXTRACTED"],
            },
            "execution": {
                "arguments": index_result["args"],
                "stdoutSha256": hashlib.sha256(index_result["stdout"].encode("utf-8")).hexdigest(),
                "stderrSha256": hashlib.sha256(index_result["stderr"].encode("utf-8")).hexdigest(),
                "sourceWrite": False,
                "gitWrite": False,
                "hostedService": False,
            },
            "normalizedGraphDigest": canonical_digest(normalized),
        }
        manifest = {**manifest_core, "manifestDigest": canonical_digest(manifest_core)}
        _atomic_json(stage / "manifest.json", manifest)
        snapshot_name = (
            f"{exact_binding['projectFingerprint']}-{manifest['manifestDigest'][:16]}"
        )
        destination = snapshots_root / snapshot_name
        if destination.exists():
            existing = load_snapshot(
                project_path,
                str(destination.relative_to(root) / "manifest.json"),
                expected_manifest_digest=manifest["manifestDigest"],
                home=actual_home,
            )
            shutil.rmtree(stage)
            return existing
        os.replace(stage, destination)
        relative_manifest = str((destination / "manifest.json").relative_to(root))
        pointer = {
            "schemaVersion": PROJECT_INTELLIGENCE_SCHEMA_VERSION,
            "manifestRelativePath": relative_manifest,
            "manifestDigest": manifest["manifestDigest"],
            "projectFingerprint": exact_binding["projectFingerprint"],
            "updatedAt": _timestamp(),
        }
        _atomic_json(root / "current.json", pointer)
        _prune_private_directories(
            snapshots_root,
            keep={destination.name},
            limit=MAX_RETAINED_SNAPSHOTS,
        )
        return {
            "manifest": manifest,
            "manifestRelativePath": relative_manifest,
            "manifestPath": str(destination / "manifest.json"),
            "graphPath": str(destination / "graph.json"),
            "visualizationPath": str(destination / "graph.html") if html_artifact else None,
        }
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def load_snapshot(
    project_path: Path,
    manifest_relative_path: str,
    *,
    expected_manifest_digest: str,
    home: Path | None = None,
) -> dict[str, Any]:
    if not _DIGEST_RE.fullmatch(str(expected_manifest_digest)):
        raise ProjectIntelligenceError("The expected snapshot manifest digest is invalid.")
    root = project_storage_root(project_path.resolve(), home=home)
    relative = Path(str(manifest_relative_path))
    if relative.is_absolute() or ".." in relative.parts or relative.name != "manifest.json":
        raise ProjectIntelligenceError("The snapshot manifest path is unsafe.")
    manifest_path = root / relative
    try:
        resolved = manifest_path.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise ProjectIntelligenceError("The snapshot manifest escapes private project storage.") from exc
    try:
        manifest = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectIntelligenceError("The private snapshot manifest is unreadable.") from exc
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != SNAPSHOT_SCHEMA_VERSION:
        raise ProjectIntelligenceError("The private snapshot manifest schema is unsupported.")
    core = {key: value for key, value in manifest.items() if key != "manifestDigest"}
    digest = canonical_digest(core)
    if digest != manifest.get("manifestDigest") or digest != expected_manifest_digest:
        raise ProjectIntelligenceError("The private snapshot manifest digest does not match its receipt.")
    if manifest.get("repositoryId") != repository_id(project_path.resolve()):
        raise ProjectIntelligenceError("The private snapshot belongs to a different repository.")
    if manifest.get("provider", {}).get("catalogDigest") != catalog_digest():
        raise ProjectIntelligenceError("The private snapshot was produced by a stale provider catalog.")
    graph_path = resolved.parent / str(manifest["graph"]["relativePath"])
    graph_size, graph_digest = _sha256_file(graph_path, maximum=MAX_GRAPH_BYTES)
    if graph_size != manifest["graph"]["bytes"] or graph_digest != manifest["graph"]["sha256"]:
        raise ProjectIntelligenceError("The private graph artifact has changed since indexing.")
    visualization_path: Path | None = None
    visualization = manifest.get("visualization")
    if visualization:
        visualization_path = resolved.parent / str(visualization["relativePath"])
        html_size, html_digest = _sha256_file(visualization_path, maximum=MAX_HTML_BYTES)
        if html_size != visualization["bytes"] or html_digest != visualization["sha256"]:
            raise ProjectIntelligenceError("The private Graphify visualization has changed since indexing.")
    return {
        "manifest": manifest,
        "manifestRelativePath": str(relative),
        "manifestPath": str(resolved),
        "graphPath": str(graph_path),
        "visualizationPath": str(visualization_path) if visualization_path else None,
    }


def _query_terms(question: str) -> list[str]:
    terms = []
    for match in _TOKEN_RE.findall(str(question or "")):
        term = match.lower().strip("._:/-")
        if len(term) >= 2 and term not in terms:
            terms.append(term)
    return terms[:32]


def focused_query(
    project_path: Path,
    graph_path: Path,
    question: str,
    *,
    max_nodes: int = 120,
    max_edges: int = 240,
    depth: int = 2,
) -> dict[str, Any]:
    if not 1 <= max_nodes <= MAX_QUERY_NODES or not 1 <= max_edges <= MAX_QUERY_EDGES:
        raise ProjectIntelligenceError("Query node or edge budget is outside the supported range.")
    if not 0 <= depth <= MAX_QUERY_DEPTH:
        raise ProjectIntelligenceError("Query depth is outside the supported range.")
    normalized, summary = _load_graph(graph_path, project_path.resolve())
    terms = _query_terms(question)
    if not terms:
        raise ProjectIntelligenceError("A bounded graph query requires at least one searchable term.")
    nodes_by_id = {node["id"]: node for node in normalized["nodes"]}
    scored: list[tuple[int, str]] = []
    for node in normalized["nodes"]:
        haystack = " ".join(
            str(node.get(field) or "") for field in ("label", "id", "sourceFile", "type")
        ).lower()
        score = sum(3 if term in str(node["label"]).lower() else 1 for term in terms if term in haystack)
        if score:
            scored.append((-score, node["id"]))
    scored.sort()
    seeds = [node_id for _, node_id in scored[: min(24, max_nodes)]]
    if not seeds:
        return {
            "schemaVersion": QUERY_SCHEMA_VERSION,
            "questionDigest": hashlib.sha256(question.encode("utf-8")).hexdigest(),
            "terms": terms,
            "seeds": [],
            "nodes": [],
            "edges": [],
            "strongEvidenceEdgeCount": 0,
            "advisoryEdgeCount": 0,
            "truncated": False,
            "graphDigest": summary["sha256"],
        }
    adjacency: dict[str, list[dict[str, Any]]] = {node_id: [] for node_id in nodes_by_id}
    for edge in normalized["edges"]:
        adjacency[edge["source"]].append(edge)
        adjacency[edge["target"]].append(edge)
    selected: set[str] = set(seeds)
    queue: deque[tuple[str, int]] = deque((seed, 0) for seed in seeds)
    while queue and len(selected) < max_nodes:
        node_id, distance = queue.popleft()
        if distance >= depth:
            continue
        for edge in sorted(adjacency.get(node_id, []), key=lambda value: value["id"]):
            neighbor = edge["target"] if edge["source"] == node_id else edge["source"]
            if neighbor not in selected:
                selected.add(neighbor)
                queue.append((neighbor, distance + 1))
                if len(selected) >= max_nodes:
                    break
    selected_edges = [
        edge
        for edge in normalized["edges"]
        if edge["source"] in selected and edge["target"] in selected
    ]
    selected_edges.sort(key=lambda value: (not value["strongEvidence"], value["id"]))
    edge_truncated = len(selected_edges) > max_edges
    selected_edges = selected_edges[:max_edges]
    connected = set(seeds)
    for edge in selected_edges:
        connected.update((edge["source"], edge["target"]))
    selected_nodes = [nodes_by_id[node_id] for node_id in sorted(connected) if node_id in nodes_by_id]
    strong = sum(1 for edge in selected_edges if edge["strongEvidence"])
    return {
        "schemaVersion": QUERY_SCHEMA_VERSION,
        "questionDigest": hashlib.sha256(question.encode("utf-8")).hexdigest(),
        "terms": terms,
        "seeds": seeds,
        "nodes": selected_nodes,
        "edges": selected_edges,
        "strongEvidenceEdgeCount": strong,
        "advisoryEdgeCount": len(selected_edges) - strong,
        "truncated": edge_truncated or len(selected) >= max_nodes,
        "budgets": {"nodes": max_nodes, "edges": max_edges, "depth": depth},
        "graphDigest": summary["sha256"],
    }


def impact_analysis(
    project_path: Path,
    graph_path: Path,
    *,
    goal: str,
    changed_paths: Sequence[str],
    max_nodes: int = 160,
    max_edges: int = 320,
    depth: int = 2,
) -> dict[str, Any]:
    safe_paths: list[str] = []
    for value in changed_paths:
        relative = _relative_source(value, project_path.resolve())
        if relative is None:
            raise ProjectIntelligenceError(f"Impact scope contains an unsafe repository path: {value!r}.")
        if relative not in safe_paths:
            safe_paths.append(relative)
    question = " ".join([goal, *safe_paths]).strip()
    query = focused_query(
        project_path,
        graph_path,
        question,
        max_nodes=max_nodes,
        max_edges=max_edges,
        depth=depth,
    )
    directly_scoped = {
        node["id"]
        for node in query["nodes"]
        if node.get("sourceFile") in set(safe_paths)
    }
    strong_impacted: set[str] = set()
    advisory_impacted: set[str] = set()
    for edge in query["edges"]:
        if edge["source"] in directly_scoped or edge["target"] in directly_scoped:
            target = edge["target"] if edge["source"] in directly_scoped else edge["source"]
            (strong_impacted if edge["strongEvidence"] else advisory_impacted).add(target)
    result = {
        "schemaVersion": IMPACT_SCHEMA_VERSION,
        "goalDigest": hashlib.sha256(goal.encode("utf-8")).hexdigest(),
        "changedPaths": safe_paths,
        "changedPathsDigest": canonical_digest(safe_paths),
        "directNodeIds": sorted(directly_scoped),
        "strongImpactedNodeIds": sorted(strong_impacted),
        "advisoryImpactedNodeIds": sorted(advisory_impacted - strong_impacted),
        "query": query,
        "evidenceBoundary": (
            "Only source-anchored EXTRACTED edges are strong impact evidence. "
            "All other graph relationships are advisory and require direct source verification."
        ),
    }
    result["impactDigest"] = canonical_digest(result)
    return result


def render_focused_graph(
    project_path: Path,
    snapshot: Mapping[str, Any],
    query: Mapping[str, Any],
    *,
    home: Path | None = None,
    executable: Path | None = None,
) -> dict[str, Any]:
    actual_home = (home or Path.home()).expanduser().resolve()
    selected_executable = (executable or managed_executable(home=actual_home)).expanduser()
    provider = discover_provider(home=actual_home, executable=selected_executable)
    if provider["status"] != "available":
        raise ProjectIntelligenceError("The pinned Graphify runtime is unavailable for focused visualization.")
    manifest = snapshot.get("manifest") if isinstance(snapshot, Mapping) else None
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("graph", {}).get("sha256") != query.get("graphDigest")
    ):
        raise ProjectIntelligenceError(
            "The focused query does not belong to the supplied immutable graph snapshot."
        )
    root = project_storage_root(project_path.resolve(), home=actual_home)
    query_digest = canonical_digest(
        {
            "graph": query.get("graphDigest"),
            "question": query.get("questionDigest"),
            "nodes": [node.get("id") for node in query.get("nodes", [])],
            "edges": [edge.get("id") for edge in query.get("edges", [])],
        }
    )
    target = _ensure_private_directory(root / "queries", home=actual_home) / query_digest
    if target.exists():
        html_path = target / "graph.html"
        size, digest = _sha256_file(html_path, maximum=MAX_HTML_BYTES)
        return {"path": str(html_path), "sha256": digest, "bytes": size, "providerNative": True}
    stage = root / "staging" / uuid.uuid4().hex
    stage.mkdir(mode=0o700, parents=True)
    runtime_home = stage / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    try:
        graph = {
            "directed": True,
            "multigraph": False,
            "graph": {},
            "nodes": [
                {
                    "id": node["id"],
                    "label": node["label"],
                    "type": node.get("type"),
                    "source_file": node.get("sourceFile"),
                    "source_location": node.get("sourceLocation"),
                }
                for node in query.get("nodes", [])
            ],
            "edges": [
                {
                    "source": edge["source"],
                    "target": edge["target"],
                    "relation": edge["relation"],
                    "confidence": edge["confidence"],
                    "source_file": edge.get("sourceFile"),
                    "source_location": edge.get("sourceLocation"),
                }
                for edge in query.get("edges", [])
            ],
        }
        _atomic_json(stage / "graph.json", graph)
        _run_provider(
            selected_executable,
            ["export", "html", "--graph", str(stage / "graph.json"), "--node-limit", "5000"],
            cwd=project_path.resolve(),
            graph_out=stage,
            runtime_home=runtime_home,
        )
        shutil.rmtree(runtime_home, ignore_errors=True)
        os.replace(stage, target)
        size, digest = _sha256_file(target / "graph.html", maximum=MAX_HTML_BYTES)
        _prune_private_directories(
            target.parent,
            keep={target.name},
            limit=MAX_RETAINED_QUERIES,
        )
        return {"path": str(target / "graph.html"), "sha256": digest, "bytes": size, "providerNative": True}
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
