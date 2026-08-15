#!/usr/bin/env python3
"""Fail-closed local orchestrator for the preregistered Beta.1 study.

This maintainer-only module deliberately refuses to start a model until the
study bundle, immutable Git registration, Apple container runtime, task image,
and isolation canaries have all been verified. It is not installed with JStack.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import datetime as dt
import selectors
import signal
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Optional

from evals.runner.contracts import ContractError, validate_manifest, validate_task

from .broker import broker_config_digest, proof_tool_descriptors, validate_broker_config
from .attempt_bundle import (
    ARTIFACT_ENTRY_NAMES,
    ARTIFACT_FILE_LIMITS,
    validate_attempt_bundle,
)
from .common import (
    ProofPlaneError,
    advance_ledger_anchor,
    atomic_publish_bytes_once,
    canonical_digest,
    file_digest,
    load_json,
    read_ledger_anchor,
    resolve_within,
    utc_now,
    validate_ledger,
    write_canonical_json_once,
)
from .controller import ReservationHandle, StudyRunController, TrustedAttemptPlan
from .executor import (
    ReadOnlyMount,
    build_model_vm_argv,
    capture_patch,
    managed_container,
    prepare_source_workspace,
)
from .grading import load_canonical_expected_run_set
from .qualification import (
    CANONICAL_FILE_DIGEST_ENCODING,
    PREFLIGHT_CHECKS,
    build_preflight_receipt,
    image_builder_attestation_summary,
    load_canonical_preflight_receipt,
    load_canonical_qualification_receipt_set,
    qualification_receipt_set_digests,
    runtime_tcb_summary,
    validate_local_image_store_observation,
    validate_runtime_tcb_summary,
)
from .qualification_runtime import inspect_local_image_store
from .runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
    AppleRuntimeTCB,
    inspect_apple_container_tcb,
    validate_apple_container_tcb_document,
)
from .study import (
    execution_schedule,
    validate_bundle,
    validate_evidence_bindings,
    validate_registration,
)
from .run_envelope import validate_model_result
from .task_artifact_summary import (
    fixed_task_artifact_set_summary_path,
    load_canonical_task_artifact_set_summary,
    task_artifact_set_summary_digests,
    validate_task_artifact_summary_bindings,
)


RUNNER_VERSION = "0.10.0-beta.1"
RUNTIME_NAME = "container"
RUNTIME_MINIMUM = (1, 0, 0)
REQUIRED_CODEX_FEATURES = {
    "apps": False,
    "auth_elicitation": False,
    "browser_use": False,
    "browser_use_external": False,
    "browser_use_full_cdp_access": False,
    "code_mode_host": False,
    "computer_use": False,
    "goals": False,
    "guardian_approval": False,
    "hooks": False,
    "image_generation": False,
    "in_app_browser": False,
    "memories": False,
    "multi_agent": False,
    "plugins": False,
    "plugin_sharing": False,
    "remote_plugin": False,
    "shell_tool": False,
    "skill_search": False,
    "skill_mcp_dependency_install": False,
    "unified_exec": False,
    "tool_suggest": False,
    "workspace_dependencies": False,
}
PROOF_TOOLS = ("proof_apply_patch", "proof_exec", "proof_git_evidence", "proof_read_file")
MODEL_RESULT_SCHEMA = "jstack.eval.model-result.v1"
MODEL_ATTEMPT_REPORT_SCHEMA = "jstack.eval.model-attempt-orchestration.v1"
CODEX_PROVENANCE_SCHEMA = "macos-codesign-v1"
FROZEN_REASONING_EFFORT = "high"
CODEX_JSONL_LINE_LIMIT = 1_000_000
CODEX_JSONL_EVENT_LIMIT = 100_000
_CODEX_EVENT_TYPES = frozenset(
    (
        "thread.started",
        "turn.started",
        "turn.completed",
        "turn.failed",
        "item.started",
        "item.updated",
        "item.completed",
        "error",
    )
)
_BLOCKED_CODEX_ERROR_CODES = frozenset(
    (
        "account_deactivated",
        "authentication_error",
        "billing_hard_limit_reached",
        "insufficient_quota",
        "model_not_found",
        "rate_limit_exceeded",
        "service_unavailable",
        "unsupported_country",
        "usage_limit_reached",
    )
)


class AttemptRecoveryRequired(ProofPlaneError):
    """A scored cell started but lacks enough verified evidence to terminalize.

    The caller must not retry the model.  A maintainer recovery controller may
    later prove teardown and complete the retained evidence, otherwise the
    preregistered study remains incomplete.
    """


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _inspect_exact_runtime_tcb(
    runtime: Path,
    expected_document: Mapping[str, Any],
    field: str,
) -> AppleRuntimeTCB:
    """Re-inspect and require the complete frozen Apple runtime TCB.

    A matching CLI digest or compact summary is insufficient here.  The live
    observation must equal the full qualification document, including every
    installed component, service/config binding, kernel, and init-image OCI
    closure.  The inspector itself has no production override seam.
    """

    expected = validate_apple_container_tcb_document(expected_document)
    observed = inspect_apple_container_tcb(runtime)
    observed_document = validate_apple_container_tcb_document(observed.document)
    if observed_document != expected:
        raise ProofPlaneError("%s differs from the qualified full runtime TCB" % field)
    if (
        observed.tcb_sha256 != expected["tcbSha256"]
        or observed.runtime_version != expected["runtime"]["version"]
        or observed.runtime_binary_sha256 != expected["runtime"]["binarySha256"]
        or observed.kernel_path != expected["kernel"]["resolvedPath"]
        or observed.kernel_sha256 != expected["kernel"]["sha256"]
        or observed.immutable_init_image_reference
        != expected["initImage"]["immutableReference"]
    ):
        raise ProofPlaneError("%s returned inconsistent runtime TCB projections" % field)
    return observed


class BoundedProcessError(ProofPlaneError):
    """A bounded command failed while retaining only its bounded capture."""

    def __init__(self, message: str, *, kind: str, stdout: bytes = b"", stderr: bytes = b"") -> None:
        super().__init__(message)
        self.kind = kind
        self.stdout = stdout
        self.stderr = stderr


def probe_mcp_tool_surface(
    command: list[str],
    *,
    expected_count: int,
    name_prefix: str,
    expected_version: str,
) -> dict[str, Any]:
    """Initialize one frozen MCP server and bind its version and tool surface."""

    if (
        not isinstance(expected_version, str)
        or not expected_version
        or expected_version != expected_version.strip()
        or len(expected_version) > 100
    ):
        raise ProofPlaneError("expected MCP server version is invalid")

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "jstack-proof-probe", "version": RUNNER_VERSION},
            },
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    payload = ("\n".join(json.dumps(item, separators=(",", ":")) for item in requests) + "\n").encode()
    completed = _run(command, stdin=payload, timeout=30, maximum_output=10_000_000)
    if completed.returncode != 0 or completed.stderr:
        raise ProofPlaneError("MCP tool-surface probe failed clean execution")
    try:
        responses = [json.loads(line) for line in completed.stdout.decode("utf-8").splitlines() if line]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProofPlaneError("MCP tool-surface probe returned invalid JSONL") from exc
    by_id = {item.get("id"): item for item in responses if isinstance(item, dict) and "id" in item}
    if set(by_id) != {1, 2} or "result" not in by_id[1] or "result" not in by_id[2]:
        raise ProofPlaneError("MCP tool-surface probe returned an incomplete protocol response")
    tools = by_id[2]["result"].get("tools") if isinstance(by_id[2]["result"], dict) else None
    if not isinstance(tools, list) or len(tools) != expected_count:
        raise ProofPlaneError("MCP tool-surface count differs from the frozen registration")
    names = []
    for index, item in enumerate(tools):
        if not isinstance(item, dict) or set(item) != {"name", "description", "inputSchema", "annotations"}:
            raise ProofPlaneError("MCP tool[%d] is not a closed canonical tool descriptor" % index)
        name = item["name"]
        if not isinstance(name, str) or not name.startswith(name_prefix):
            raise ProofPlaneError("MCP tool[%d] has an unexpected name" % index)
        names.append(name)
    if len(set(names)) != expected_count:
        raise ProofPlaneError("MCP tool-surface contains duplicate names")
    canonical_tools = sorted((dict(item) for item in tools), key=lambda item: item["name"])
    initialize = by_id[1]["result"]
    if not isinstance(initialize, dict):
        raise ProofPlaneError("MCP initialize result is invalid")
    server_info = initialize.get("serverInfo")
    if (
        not isinstance(server_info, dict)
        or set(server_info) != {"name", "version"}
        or server_info.get("name") != "jstack-mcp"
        or server_info.get("version") != expected_version
    ):
        raise ProofPlaneError(
            "MCP initialize server version differs from the frozen registration"
        )
    return {
        "count": expected_count,
        "names": sorted(names),
        "toolsSha256": canonical_digest(canonical_tools),
        "initializeSha256": canonical_digest(initialize),
        "serverVersion": expected_version,
    }


def _run(
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    stdin: Optional[bytes] = None,
    timeout: int = 30,
    maximum_output: int = 2_000_000,
) -> subprocess.CompletedProcess[bytes]:
    if not args or not all(isinstance(item, str) and item for item in args):
        raise ProofPlaneError("runner command argv is invalid")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 3_600:
        raise ProofPlaneError("runner command timeout is invalid")
    if (
        not isinstance(maximum_output, int)
        or isinstance(maximum_output, bool)
        or maximum_output < 1_024
        or maximum_output > 20_000_000
    ):
        raise ProofPlaneError("runner command output limit is invalid")
    if stdin is not None and (not isinstance(stdin, bytes) or len(stdin) > 1_000_000):
        raise ProofPlaneError("runner command stdin exceeds the 1 MB limit")
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    with tempfile.TemporaryFile() as input_handle:
        if stdin is not None:
            input_handle.write(stdin)
            input_handle.seek(0)
        try:
            process = subprocess.Popen(
                args,
                cwd=cwd,
                env=environment,
                stdin=input_handle if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BoundedProcessError("runner command could not start", kind="start-failed") from exc
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        failure: Optional[str] = None
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "runner command timed out"
                    break
                ready = selector.select(min(remaining, 0.5))
                if not ready and process.poll() is not None:
                    # A final zero-time pass drains EOF from both pipes.
                    ready = selector.select(0)
                    if not ready:
                        break
                for key, _mask in ready:
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    stream = str(key.data)
                    if sum(len(item) for item in captured.values()) + len(chunk) > maximum_output:
                        failure = "runner command output exceeded the bounded capture limit"
                        break
                    captured[stream].extend(chunk)
                if failure:
                    break
        finally:
            if failure:
                _kill_process_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired as exc:
                    raise ProofPlaneError("runner command process group could not be reaped") from exc
            selector.close()
            process.stdout.close()
            process.stderr.close()
        if failure:
            kind = "timed-out" if failure == "runner command timed out" else "output-limit"
            raise BoundedProcessError(
                failure,
                kind=kind,
                stdout=bytes(captured["stdout"]),
                stderr=bytes(captured["stderr"]),
            )
        return subprocess.CompletedProcess(
            args,
            int(process.returncode),
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
        )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill a command and descendants without assuming POSIX in import-time tests."""

    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - the Beta executor itself is macOS-only
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _version_tuple(text: str) -> tuple[int, int, int]:
    pieces = []
    for token in text.replace("-", " ").split():
        if token[:1].isdigit():
            for item in token.split("."):
                digits = "".join(char for char in item if char.isdigit())
                if not digits:
                    break
                pieces.append(int(digits))
            if pieces:
                break
    return tuple((pieces + [0, 0, 0])[:3])


def codex_cli_provenance(codex_path: Path) -> str:
    """Return one deterministic Apple code-signing identity for the frozen CLI.

    The executable bytes are bound separately.  This provenance binding prevents
    a look-alike executable from satisfying the study merely by printing the
    registered ``codex --version`` line.
    """

    resolved = codex_path.resolve()
    if not resolved.is_absolute() or resolved.is_symlink() or not resolved.is_file():
        raise ProofPlaneError("Codex CLI must resolve to a regular non-symlink executable")
    verify = _run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(resolved)],
        timeout=30,
        maximum_output=200_000,
    )
    if verify.returncode != 0:
        raise ProofPlaneError("Codex CLI does not have a valid strict macOS code signature")
    details = _run(
        ["/usr/bin/codesign", "-dv", "--verbose=4", str(resolved)],
        timeout=30,
        maximum_output=200_000,
    )
    if details.returncode != 0:
        raise ProofPlaneError("Codex CLI signing identity could not be inspected")
    values: dict[str, str] = {}
    for raw_line in (details.stdout + details.stderr).decode("utf-8", errors="strict").splitlines():
        if "=" not in raw_line:
            continue
        key, item = raw_line.split("=", 1)
        if key in ("Identifier", "TeamIdentifier", "CandidateCDHashFull sha256"):
            if key in values or not item or item != item.strip():
                raise ProofPlaneError("Codex CLI signing identity is ambiguous")
            values[key] = item
    if set(values) != {"Identifier", "TeamIdentifier", "CandidateCDHashFull sha256"}:
        raise ProofPlaneError("Codex CLI signing identity is incomplete")
    if (
        values["Identifier"] != "codex"
        or values["TeamIdentifier"] != "2DC432GLL2"
        or len(values["CandidateCDHashFull sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in values["CandidateCDHashFull sha256"])
    ):
        raise ProofPlaneError("Codex CLI is not the registered OpenAI Developer ID binary")
    return "%s:identifier=%s;team=%s;cdhash=%s" % (
        CODEX_PROVENANCE_SCHEMA,
        values["Identifier"],
        values["TeamIdentifier"],
        values["CandidateCDHashFull sha256"],
    )


def codex_cli_registration_binding(codex_path: Path) -> dict[str, str]:
    """Derive the closed host fields used by preregistration.

    The executable path is selected by the maintainer lifecycle, never by the
    candidate document.  This helper binds the same version command, bytes,
    and Apple signing identity that preflight later rechecks.
    """

    if (
        not isinstance(codex_path, Path)
        or not codex_path.is_absolute()
        or codex_path.is_symlink()
        or not codex_path.is_file()
        or not os.access(codex_path, os.X_OK)
    ):
        raise ProofPlaneError("Codex CLI must be an absolute regular executable")
    completed = _run(
        [str(codex_path), "--version"], timeout=15, maximum_output=100_000
    )
    if completed.returncode != 0 or completed.stderr:
        raise ProofPlaneError("Codex CLI version query failed clean execution")
    try:
        rendered = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError as exc:
        raise ProofPlaneError("Codex CLI version response is not UTF-8") from exc
    pieces = rendered.split()
    if (
        len(pieces) != 2
        or pieces[0] != "codex-cli"
        or not pieces[1]
        or len(pieces[1]) > 100
        or any(character in pieces[1] for character in ("\x00", "\r", "\n"))
    ):
        raise ProofPlaneError("Codex CLI version response is not the closed host form")
    return {
        "name": pieces[0],
        "version": pieces[1],
        "binarySha256": file_digest(codex_path),
        "provenance": codex_cli_provenance(codex_path),
    }


def codex_command(
    *,
    codex_path: Path,
    empty_home: Path,
    broker_config: Path,
    repo_root: Path,
    model: str,
    reasoning_effort: str,
    jstack_mcp: Optional[Mapping[str, Any]] = None,
) -> list[str]:
    broker_command = [
        str(Path(shutil.which("python3") or "/usr/bin/python3").resolve()),
        "-m",
        "tools.proof_plane.broker",
        str(broker_config),
    ]
    overrides = {
        "web_search": "disabled",
        "sandbox_mode": "read-only",
        "approval_policy": "never",
        "history.persistence": "none",
        "model_reasoning_effort": reasoning_effort,
        "mcp_servers.proof.command": broker_command[0],
        "mcp_servers.proof.args": broker_command[1:],
        "mcp_servers.proof.cwd": str(repo_root),
        "mcp_servers.proof.required": True,
        "mcp_servers.proof.enabled": True,
        "mcp_servers.proof.enabled_tools": list(PROOF_TOOLS),
        "mcp_servers.proof.startup_timeout_sec": 10,
        "mcp_servers.proof.tool_timeout_sec": 1810,
        "mcp_servers.proof.default_tools_approval_mode": "approve",
    }
    for feature, enabled in REQUIRED_CODEX_FEATURES.items():
        overrides["features." + feature] = enabled
    if jstack_mcp is not None:
        exact = {
            "runtimeCommand",
            "containerId",
            "user",
            "serverPath",
            "enabledTools",
            "toolTimeoutSeconds",
        }
        if not isinstance(jstack_mcp, Mapping) or set(jstack_mcp) != exact:
            raise ProofPlaneError("operational JStack MCP configuration fields are invalid")
        runtime = Path(jstack_mcp["runtimeCommand"])
        if not runtime.is_absolute() or not isinstance(jstack_mcp["containerId"], str):
            raise ProofPlaneError("operational JStack MCP runtime binding is invalid")
        user = jstack_mcp["user"]
        if not isinstance(user, str) or user.startswith("0:") or user.endswith(":0"):
            raise ProofPlaneError("operational JStack MCP must use a non-root numeric user")
        server_path = jstack_mcp["serverPath"]
        if not isinstance(server_path, str) or not server_path.startswith("/opt/jstack/"):
            raise ProofPlaneError("operational JStack MCP server path is invalid")
        tools = jstack_mcp["enabledTools"]
        if (
            not isinstance(tools, list)
            or len(tools) != 52
            or len(set(tools)) != 52
            or not all(isinstance(item, str) and item.startswith("jstack_") for item in tools)
        ):
            raise ProofPlaneError("operational JStack MCP must expose exactly 52 canonical JStack tools")
        tool_timeout = jstack_mcp["toolTimeoutSeconds"]
        if not isinstance(tool_timeout, int) or isinstance(tool_timeout, bool) or not 1 <= tool_timeout <= 1900:
            raise ProofPlaneError("operational JStack MCP timeout is invalid")
        isolated_command = [
            str(runtime),
            "exec",
            "--interactive",
            "--user",
            user,
            "--workdir",
            "/workspace",
            jstack_mcp["containerId"],
            "/usr/bin/bwrap",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            "/workspace",
            "/workspace",
            "--ro-bind",
            "/proof-git",
            "/proof-git",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/tmp/home",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp/home",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "GIT_DIR",
            "/proof-git",
            "--setenv",
            "GIT_WORK_TREE",
            "/workspace",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--chdir",
            "/workspace",
            "--",
            "/usr/bin/python3",
            server_path,
        ]
        overrides.update(
            {
                "mcp_servers.jstack.command": isolated_command[0],
                "mcp_servers.jstack.args": isolated_command[1:],
                "mcp_servers.jstack.required": True,
                "mcp_servers.jstack.enabled": True,
                "mcp_servers.jstack.enabled_tools": tools,
                "mcp_servers.jstack.startup_timeout_sec": 20,
                "mcp_servers.jstack.tool_timeout_sec": tool_timeout,
                "mcp_servers.jstack.default_tools_approval_mode": "approve",
            }
        )
    command = [
        str(codex_path),
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--strict-config",
        "--sandbox",
        "read-only",
        "--json",
        "--model",
        model,
        "-C",
        str(empty_home),
    ]
    for key, value in sorted(overrides.items()):
        command.extend(["-c", "%s=%s" % (key, json.dumps(value, separators=(",", ":")))])
    command.append("-")
    return command


def _git_output(repo_root: Path, args: list[str]) -> str:
    completed = _run(["git", "-C", str(repo_root), *args], timeout=30)
    if completed.returncode != 0:
        raise ProofPlaneError("Git registration check failed: %s" % completed.stderr.decode(errors="replace").strip())
    return completed.stdout.decode("utf-8", errors="strict").strip()


def verify_registration_ref(registration: Mapping[str, Any], repo_root: Path) -> dict[str, Any]:
    if _git_output(repo_root, ["status", "--porcelain=v1", "--untracked-files=all"]):
        raise ProofPlaneError("study repository must be clean before any registered attempt")
    reference = registration["registrationRef"]
    ref_type = _git_output(repo_root, ["cat-file", "-t", reference])
    if ref_type != "tag":
        raise ProofPlaneError("registrationRef must be an annotated tag")
    commit = _git_output(repo_root, ["rev-parse", reference + "^{}"])
    if len(commit) != 40:
        raise ProofPlaneError("registrationRef did not resolve to one full Git commit")
    head = _git_output(repo_root, ["rev-parse", "HEAD"])
    if head != commit:
        raise ProofPlaneError("registered study must execute from its exact tagged commit")
    tag_object = _git_output(repo_root, ["rev-parse", reference])
    remotes = _git_output(
        repo_root,
        ["ls-remote", "--tags", "origin", reference, reference + "^{}"],
    ).splitlines()
    remote_refs: dict[str, str] = {}
    for line in remotes:
        pieces = line.split("\t")
        if len(pieces) != 2:
            raise ProofPlaneError("origin returned a malformed registration tag binding")
        digest, remote_reference = pieces
        if (
            len(digest) != 40
            or any(character not in "0123456789abcdef" for character in digest)
            or remote_reference not in (reference, reference + "^{}")
            or remote_reference in remote_refs
        ):
            raise ProofPlaneError("origin returned an invalid registration tag binding")
        remote_refs[remote_reference] = digest
    if remote_refs.get(reference) != tag_object or remote_refs.get(reference + "^{}") != commit:
        raise ProofPlaneError(
            "published registration tag object and peeled commit must exactly match the local annotated tag"
        )
    tag_timestamp_text = _git_output(repo_root, ["for-each-ref", "--format=%(taggerdate:unix)", reference])
    if not tag_timestamp_text.isdigit():
        raise ProofPlaneError("registrationRef must carry one annotated tagger timestamp")
    tag_timestamp = int(tag_timestamp_text)
    created = registration["createdAt"].replace("Z", "+00:00")
    created_timestamp = dt.datetime.fromisoformat(created).timestamp()
    if tag_timestamp + 5 < created_timestamp:
        raise ProofPlaneError("registration tag predates the declared registration timestamp inconsistently")
    return {
        "commit": commit,
        "tagObject": tag_object,
        "taggerTimestamp": tag_timestamp,
    }


def _verify_task_artifacts(task: Mapping[str, Any], *, repo_root: Path, artifact_root: Path) -> None:
    brief = resolve_within(repo_root, task["brief"]["path"], "task brief")
    if file_digest(brief) != task["brief"]["sha256"]:
        raise ProofPlaneError("task %s brief digest mismatch" % task["taskId"])
    task_root = resolve_within(artifact_root, task["taskId"], "private task artifact directory")
    if task_root.is_symlink() or not task_root.is_dir():
        raise ProofPlaneError("task %s private artifact directory is missing" % task["taskId"])
    expected = {
        "source.tar": task["source"]["sourceArchiveSha256"],
        "baseline-result.json": task["baseline"]["testResultSha256"],
        "holdout.bundle": task["holdout"]["hiddenTestBundleSha256"],
        "image-build-manifest.json": task["environment"]["toolVersions"].get(
            "image-build-manifest-sha256"
        ),
        "image-build-receipt.json": task["environment"]["toolVersions"].get(
            "image-build-receipt-sha256"
        ),
        "oci-artifact-inspection-receipt.json": task["environment"]["toolVersions"].get(
            "image-artifact-inspection-receipt-sha256"
        ),
    }
    for name, digest in expected.items():
        _sha256(digest, "task %s %s digest" % (task["taskId"], name))
        path = resolve_within(task_root, name, "private task artifact")
        if file_digest(path) != digest:
            raise ProofPlaneError("task %s %s digest mismatch" % (task["taskId"], name))


def _task_artifact_summary_rows(
    task_entries: Mapping[str, tuple[Mapping[str, Any], Path]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Derive the public digest-only summary rows from registered descriptors."""

    artifact_rows = []
    registered_rows = []
    for task_id in sorted(task_entries):
        task, task_path = task_entries[task_id]
        if task.get("taskId") != task_id:
            raise ProofPlaneError("task-artifact summary task identity drifted")
        tools = task["environment"]["toolVersions"]
        artifact_row = {
            "taskId": task_id,
            "sourceArchiveSha256": task["source"]["sourceArchiveSha256"],
            "holdoutBundleRawSha256": task["holdout"]["hiddenTestBundleSha256"],
            "baselineResultRawSha256": task["baseline"]["testResultSha256"],
            "imageBuildManifestSha256": tools.get("image-build-manifest-sha256"),
            "imageBuildReceiptSha256": tools.get("image-build-receipt-sha256"),
            "imageArtifactInspectionReceiptSha256": tools.get(
                "image-artifact-inspection-receipt-sha256"
            ),
        }
        for name, digest in artifact_row.items():
            if name != "taskId":
                _sha256(digest, "task %s summary %s" % (task_id, name))
        artifact_rows.append(artifact_row)
        registered_rows.append(
            {
                "taskId": task_id,
                "descriptorRawSha256": file_digest(task_path),
                "taskDigest": canonical_digest(dict(task)),
            }
        )
    return artifact_rows, registered_rows


def _verify_private_root(path: Path, field: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ProofPlaneError("%s must be an absolute, private, non-symlink directory" % field)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return path.resolve()


def preflight(
    registration_path: Path,
    *,
    repo_root: Path,
    artifact_root: Path,
    qualification_receipt_set_path: Path,
    task_artifact_set_summary_path: Path,
) -> dict[str, Any]:
    """Recompute every live admission binding and emit an all-pass receipt.

    A self-declared receipt is never accepted here: the registration, Git tag,
    manifest, harness, runtime, Codex executable, MCP surface, private task
    artifacts, and exact 18-image qualification set are all reloaded from their
    independently frozen sources. Any failed check raises before a receipt can
    authorize model execution.
    """

    artifact_root = _verify_private_root(artifact_root, "artifact_root")
    private_root = artifact_root.parent
    if artifact_root != private_root / "task-artifacts":
        raise ProofPlaneError(
            "artifact_root must use the fixed private task-artifacts path"
        )
    fixed_task_artifact_set_summary_path(
        private_root, task_artifact_set_summary_path
    )
    bundle = validate_bundle(registration_path, repo_root=repo_root)
    registration = validate_registration(load_json(registration_path), repo_root=repo_root)
    registered_runtime_tcb = validate_runtime_tcb_summary(
        registration["executor"]["runtimeTcb"],
        "registered executor runtimeTcb",
    )
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ProofPlaneError("Beta1 executor requires Apple silicon macOS")
    runtime_string = shutil.which(RUNTIME_NAME)
    if not runtime_string:
        raise ProofPlaneError("Apple container runtime is missing; install and qualify the pinned signed runtime")
    runtime = Path(runtime_string).resolve()
    if not runtime.is_file() or not os.access(runtime, os.X_OK):
        raise ProofPlaneError("Apple container runtime path is not a regular executable")
    version_result = _run([str(runtime), "--version"], timeout=15)
    version_text = (version_result.stdout + version_result.stderr).decode("utf-8", errors="replace")
    observed_version = _version_tuple(version_text)
    registered_version = _version_tuple(registration["executor"]["version"])
    if version_result.returncode != 0 or observed_version < RUNTIME_MINIMUM:
        raise ProofPlaneError("Apple container runtime 1.0.0 or newer is required")
    if registered_version < RUNTIME_MINIMUM or observed_version != registered_version:
        raise ProofPlaneError("Apple container version does not match the preregistration")
    git_binding = verify_registration_ref(registration, repo_root)
    if file_digest(runtime) != registration["executor"]["runtimeSha256"]:
        raise ProofPlaneError("Apple container runtime binary digest does not match the registration")
    codex_string = shutil.which("codex")
    if not codex_string:
        raise ProofPlaneError("the registered Codex CLI is missing")
    codex = Path(codex_string).resolve()
    if not codex.is_file() or not os.access(codex, os.X_OK):
        raise ProofPlaneError("Codex CLI path does not resolve to a regular executable")
    if file_digest(codex) != registration["executor"]["codexCliBinarySha256"]:
        raise ProofPlaneError("Codex CLI binary digest does not match the preregistration")
    provenance = codex_cli_provenance(codex)
    if provenance != registration["executor"]["codexCliProvenance"]:
        raise ProofPlaneError("Codex CLI signing provenance does not match the preregistration")
    codex_version = _run([str(codex), "--version"], timeout=15, maximum_output=100_000)
    expected_codex_version = "%s %s" % (registration["host"]["name"], registration["host"]["version"])
    if (
        codex_version.returncode != 0
        or codex_version.stderr
        or codex_version.stdout.decode("utf-8", errors="strict").strip() != expected_codex_version
    ):
        raise ProofPlaneError("Codex CLI version differs from the preregistration")
    server_path = resolve_within(
        repo_root,
        registration["executor"]["jstackMcpServerPath"],
        "executor JStack MCP server",
    )
    if file_digest(server_path) != registration["executor"]["jstackMcpServerSha256"]:
        raise ProofPlaneError("registered JStack MCP server digest does not match its source file")
    tool_surface = probe_mcp_tool_surface(
        [str(Path(shutil.which("python3") or "/usr/bin/python3").resolve()), str(server_path)],
        expected_count=registration["executor"]["jstackMcpToolCount"],
        name_prefix="jstack_",
        expected_version=registration["targetJStackVersion"],
    )
    if tool_surface["toolsSha256"] != registration["executor"]["jstackMcpToolsSha256"]:
        raise ProofPlaneError("registered JStack MCP tool surface differs from the live server")

    manifest = validate_manifest(load_json(resolve_within(repo_root, registration["manifestPath"], "manifest")))
    evidence_bindings_path = resolve_within(
        repo_root,
        registration["evidencePlan"]["bindingsPath"],
        "study evidence bindings",
    )
    evidence_bindings_sha256 = file_digest(evidence_bindings_path)
    tasks = []
    task_entries: dict[str, tuple[Mapping[str, Any], Path]] = {}
    for relative in manifest["taskFiles"]:
        task_path = resolve_within(repo_root, relative, "task file")
        task = validate_task(load_json(task_path))
        _verify_task_artifacts(task, repo_root=repo_root, artifact_root=artifact_root)
        tools = task["environment"]["toolVersions"]
        required_image_tools = {
            "python",
            "bubblewrap",
            "coreutils",
            "jstack-proof-canary-version",
            "jstack-proof-canary-sha256",
            "jstack-proof-grader-version",
            "jstack-proof-grader-sha256",
            "jstack-proof-runtime-sha256",
            "jstack-mcp-server-sha256",
            "jstack-mcp-tools-sha256",
            "jstack-mcp-tool-count",
            "image-build-manifest-sha256",
            "image-build-receipt-sha256",
            "image-artifact-inspection-receipt-sha256",
            "image-qualification-result-sha256",
            "source-content-sha256",
        }
        if not required_image_tools.issubset(tools):
            raise ProofPlaneError(
                "task %s image lacks qualified isolation/build tool bindings" % task["taskId"]
            )
        if tools["jstack-proof-canary-version"] != "jstack-proof-canary-v1":
            raise ProofPlaneError("task %s uses an unsupported isolation canary" % task["taskId"])
        if tools["jstack-proof-grader-version"] != "jstack-proof-grader-v1":
            raise ProofPlaneError("task %s uses an unsupported sealed grader" % task["taskId"])
        for field in (
            "jstack-proof-canary-sha256",
            "jstack-proof-grader-sha256",
            "jstack-proof-runtime-sha256",
            "jstack-mcp-server-sha256",
            "jstack-mcp-tools-sha256",
            "image-build-manifest-sha256",
            "image-build-receipt-sha256",
            "image-artifact-inspection-receipt-sha256",
            "image-qualification-result-sha256",
            "source-content-sha256",
        ):
            digest = tools[field]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise ProofPlaneError("task %s %s is not an exact SHA-256" % (task["taskId"], field))
        operational = registration["modes"]["operational"]["conditions"]["jstack"]
        if (
            tools["jstack-mcp-server-sha256"] != operational["jstackMcpServerSha256"]
            or tools["jstack-mcp-tools-sha256"] != operational["jstackMcpToolsDigest"]
            or tools["jstack-mcp-tool-count"] != str(operational["jstackMcpToolCount"])
        ):
            raise ProofPlaneError("task %s image JStack MCP binding differs from the registration" % task["taskId"])
        if tools["jstack-proof-runtime-sha256"] != registration["executor"]["runtimeSha256"]:
            raise ProofPlaneError("task %s qualified runtime differs from the registration" % task["taskId"])
        if task["taskId"] in task_entries:
            raise ProofPlaneError("manifest contains a duplicate taskId")
        tasks.append(task)
        task_entries[task["taskId"]] = (task, task_path)

    task_ids = tuple(sorted(item["taskId"] for item in tasks))
    task_artifacts = load_canonical_task_artifact_set_summary(
        task_artifact_set_summary_path,
        expected_task_ids=task_ids,
    )
    artifact_rows, registered_rows = _task_artifact_summary_rows(task_entries)
    task_artifacts = validate_task_artifact_summary_bindings(
        task_artifacts,
        study_id=registration["studyId"],
        artifact_rows=artifact_rows,
        registered_task_rows=registered_rows,
    )
    qualification_set = load_canonical_qualification_receipt_set(
        qualification_receipt_set_path,
        expected_task_ids=task_ids,
        registered_receipt_set_sha256=registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        registered_command_map_sha256=registration["executor"][
            "isolationQualificationCommandSha256"
        ],
    )
    qualification_by_task = {
        item["taskId"]: item for item in qualification_set["results"]
    }
    expected_identity = {"uid": 10001, "gid": 10001}
    expected_runtime = {
        "name": "apple-container",
        "version": registration["executor"]["version"],
        "binarySha256": registration["executor"]["runtimeSha256"],
    }
    qualified_runtime_tcb = validate_apple_container_tcb_document(
        qualification_set["runtimeTcb"]
    )
    if runtime_tcb_summary(qualified_runtime_tcb) != registered_runtime_tcb:
        raise ProofPlaneError(
            "qualification runtime TCB differs from the registered executor"
        )
    live_runtime_tcb = _inspect_exact_runtime_tcb(
        runtime,
        qualified_runtime_tcb,
        "preflight live runtime TCB",
    )
    if live_runtime_tcb.tcb_sha256 != registered_runtime_tcb["tcbSha256"]:
        raise ProofPlaneError("preflight live runtime TCB digest differs from registration")
    for task in tasks:
        task_id = task["taskId"]
        result = qualification_by_task[task_id]
        task_tools = task["environment"]["toolVersions"]
        if result["studyId"] != registration["studyId"]:
            raise ProofPlaneError("task %s qualification study binding mismatch" % task_id)
        if result["runtime"] != expected_runtime or result["identity"] != expected_identity:
            raise ProofPlaneError("task %s qualification runtime or identity mismatch" % task_id)
        if result["image"] != {
            "reference": task["environment"]["imageReference"],
            "digest": task["environment"]["imageDigest"],
        }:
            raise ProofPlaneError("task %s qualification image binding mismatch" % task_id)
        if result["imageEvidence"] != {
            "imageBuildManifestSha256": task_tools[
                "image-build-manifest-sha256"
            ],
            "imageBuildReceiptSha256": task_tools["image-build-receipt-sha256"],
            "imageArtifactInspectionReceiptSha256": task_tools[
                "image-artifact-inspection-receipt-sha256"
            ],
        }:
            raise ProofPlaneError(
                "task %s qualification image-evidence binding mismatch" % task_id
            )
        if any(task_tools.get(name) != version for name, version in result["qualifiedToolVersions"].items()):
            raise ProofPlaneError("task %s qualified tool versions differ from its descriptor" % task_id)
        if (
            task_tools["image-qualification-result-sha256"]
            != qualification_set["resultFileSha256ByTask"][task_id]
        ):
            raise ProofPlaneError("task %s qualification-result file digest mismatch" % task_id)
        if result["canary"]["policySha256"] != registration["executor"]["policySha256"]:
            raise ProofPlaneError("task %s isolation canary policy differs from the runner" % task_id)
        qualified_store = validate_local_image_store_observation(
            result["imageAliasVerification"]["storeAfter"],
            image_reference=task["environment"]["imageReference"],
            image_digest=task["environment"]["imageDigest"],
            field="task %s qualified image-store observation" % task_id,
        )
        live_store = inspect_local_image_store(
            runtime,
            live_runtime_tcb.document,
            task["environment"]["imageReference"],
            task["environment"]["imageDigest"],
        )
        if live_store != qualified_store:
            raise ProofPlaneError(
                "task %s live image store differs from qualification" % task_id
            )

    schedule = execution_schedule(manifest["executionPlan"]["expectedRuns"], registration["schedule"]["seedSha256"])
    schedule_sha256 = canonical_digest(schedule)
    proof_tools_sha256 = canonical_digest(proof_tool_descriptors())
    for mode in ("controlled", "operational"):
        for condition in ("plain", "jstack"):
            if (
                registration["modes"][mode]["conditions"][condition]["proofBrokerToolsDigest"]
                != proof_tools_sha256
            ):
                raise ProofPlaneError("registered proof-broker tool surface differs from the runner")
    tool_surface_body = {
        "proofBrokerToolsSha256": proof_tools_sha256,
        "proofBrokerToolCount": len(PROOF_TOOLS),
        "jstackMcpServerSha256": registration["executor"]["jstackMcpServerSha256"],
        "jstackMcpToolsSha256": tool_surface["toolsSha256"],
        "jstackMcpToolCount": tool_surface["count"],
    }
    tool_surface_binding = {
        **tool_surface_body,
        "combinedSha256": canonical_digest(tool_surface_body),
    }
    qualification_digests = qualification_receipt_set_digests(
        qualification_set,
        expected_task_ids=task_ids,
    )
    if qualification_digests["rawCanonicalFileSha256"] != registration["executor"][
        "isolationQualificationReceiptSetSha256"
    ]:
        raise ProofPlaneError("qualification set raw digest changed during preflight")
    if qualification_set["commandMapSha256"] != registration["executor"][
        "isolationQualificationCommandSha256"
    ]:
        raise ProofPlaneError("qualification command-map digest changed during preflight")
    builder_attestation = image_builder_attestation_summary(
        qualification_set["imageBuilderAttestation"],
        expected_task_ids=task_ids,
    )
    if builder_attestation != registration["executor"]["imageBuilderAttestation"]:
        raise ProofPlaneError(
            "image-builder attestation changed during preflight"
        )

    checks = {name: True for name in PREFLIGHT_CHECKS}
    return build_preflight_receipt(
        study_id=bundle["studyId"],
        registration_sha256=bundle["registrationSha256"],
        manifest_sha256=bundle["manifestSha256"],
        evidence_bindings_sha256=evidence_bindings_sha256,
        execution_schedule_sha256=schedule_sha256,
        registration_tag={
            "reference": registration["registrationRef"],
            "objectFormat": "sha1",
            "tagObject": git_binding["tagObject"],
            "commit": git_binding["commit"],
        },
        harness_lock_sha256=registration["executor"]["harnessLockSha256"],
        runtime=expected_runtime,
        codex={
            "version": expected_codex_version,
            "binarySha256": registration["executor"]["codexCliBinarySha256"],
            "provenance": provenance,
        },
        tool_surface=tool_surface_binding,
        qualification_receipt_set=qualification_set,
        expected_task_ids=task_ids,
        registered_qualification_receipt_set_sha256=qualification_digests[
            "rawCanonicalFileSha256"
        ],
        registered_qualification_command_sha256=qualification_set["commandMapSha256"],
        registered_image_builder_attestation=builder_attestation,
        task_artifact_set_summary=task_artifacts,
        checks=checks,
        checked_at=utc_now(),
    )


def isolation_canary_script() -> str:
    """Return the fixed launcher for the compiled, digest-bound canary."""

    return (
        'set -eu\n'
        'actual="$(sha256sum /usr/local/bin/jstack-proof-canary | cut -d" " -f1)"\n'
        'test "$actual" = "$1"\n'
        'exec /usr/local/bin/jstack-proof-canary\n'
    )


def _attempt_path(private_root: Path, run_id: str, suffix: str) -> Path:
    if not isinstance(run_id, str) or not run_id or len(run_id) > 500 or run_id != run_id.strip():
        raise ProofPlaneError("runId is invalid")
    private_root = _verify_private_root(private_root, "private_root")
    attempts = private_root / "attempts"
    return attempts / (hashlib.sha256(run_id.encode()).hexdigest() + suffix)


def _ensure_private_directory(path: Path, field: str) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise ProofPlaneError("%s path must be a non-symlink directory" % field)
    path.mkdir(parents=False, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise ProofPlaneError("could not protect the %s directory" % field) from exc


def attempt_evidence_paths(private_root: Path, run_id: str) -> dict[str, Path]:
    """Return deterministic private paths for one frozen primary attempt."""

    start = _attempt_path(private_root, run_id, ".start.json")
    _ensure_private_directory(start.parent, "attempts")
    slug = hashlib.sha256(run_id.encode()).hexdigest()
    result = {"start": start, "terminal": start.with_name(slug + ".terminal.json")}
    for directory_name, key, suffix in (
        ("ledgers", "ledger", ".jsonl"),
        ("anchors", "anchor", ".anchor.json"),
    ):
        directory = private_root / directory_name
        _ensure_private_directory(directory, directory_name)
        result[key] = directory / (slug + suffix)
    return result


def _create_empty_regular(path: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ProofPlaneError("primary attempt ledger already exists") from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exclusive_json(path: Path, value: Mapping[str, Any]) -> None:
    write_canonical_json_once(path, dict(value), mode=0o600)


def terminalize_attempt(
    *,
    run_id: str,
    private_root: Path,
    terminal: Mapping[str, Any],
) -> Path:
    """Persist one primary terminal receipt without permitting replacement."""

    if not isinstance(terminal, Mapping):
        raise ProofPlaneError("terminal attempt evidence must be an object")
    status = terminal.get("status")
    if status not in ("completed", "failed", "blocked", "timed-out"):
        raise ProofPlaneError("attempt terminal status is invalid")
    paths = attempt_evidence_paths(private_root, run_id)
    start = paths["start"]
    if start.is_symlink() or not start.is_file():
        raise ProofPlaneError("a write-once primary start receipt is required before terminalization")
    start_value = load_json(start, maximum_bytes=100_000)
    if start_value.get("runId") != run_id:
        raise ProofPlaneError("primary start receipt run binding is invalid")
    anchor = read_ledger_anchor(paths["anchor"])
    genesis_anchor_sha256 = start_value.get("genesisAnchorSha256")
    _sha256(genesis_anchor_sha256, "primary start genesis anchor")
    if anchor["revision"] == 0:
        if anchor["anchorSha256"] != genesis_anchor_sha256:
            raise ProofPlaneError("primary ledger genesis anchor differs from the start receipt")
    elif anchor["revision"] == 1:
        if anchor["previousAnchorSha256"] != genesis_anchor_sha256:
            raise ProofPlaneError("primary ledger anchor does not descend from genesis")
    else:
        raise ProofPlaneError("primary ledger anchor revision exceeds retained ancestry")
    entries = validate_ledger(paths["ledger"])
    if len(entries) < anchor["recordCount"]:
        raise ProofPlaneError("primary ledger was truncated below its external anchor")
    if len(entries) > anchor["recordCount"]:
        if anchor["revision"] != 0:
            raise ProofPlaneError("primary ledger requires an unretained anchor revision")
        anchor = advance_ledger_anchor(
            paths["anchor"],
            paths["ledger"],
            expected_record_count=anchor["recordCount"],
            expected_head_sha256=anchor["terminalHeadSha256"],
            expected_anchor_sha256=anchor["anchorSha256"],
        )
        if (
            anchor["revision"] != 1
            or anchor["previousAnchorSha256"] != genesis_anchor_sha256
        ):
            raise ProofPlaneError("advanced primary ledger anchor has invalid ancestry")
    entries = validate_ledger(
        paths["ledger"],
        anchor_path=paths["anchor"],
        expected_record_count=anchor["recordCount"],
        expected_head_sha256=anchor["terminalHeadSha256"],
        expected_anchor_sha256=anchor["anchorSha256"],
    )
    target = paths["terminal"]
    payload = {
        "schemaVersion": "jstack.eval.primary-attempt-terminal.v1",
        "runId": run_id,
        "recordedAt": utc_now(),
        "startReceiptSha256": file_digest(start),
        "ledgerSha256": file_digest(paths["ledger"]),
        "ledgerRecordCount": len(entries),
        "ledgerHeadSha256": anchor["terminalHeadSha256"],
        "ledgerAnchorSha256": anchor["anchorSha256"],
        "ledgerAnchorRevision": anchor["revision"],
        "terminal": dict(terminal),
    }
    _exclusive_json(target, payload)
    return target


def _closed_json_value(value: Any, field: str) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ProofPlaneError("%s contains an invalid Unicode scalar" % field) from exc
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProofPlaneError("%s contains a non-finite number" % field)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _closed_json_value(item, "%s[%d]" % (field, index))
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProofPlaneError("%s contains a non-string object key" % field)
            try:
                key.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ProofPlaneError("%s contains an invalid Unicode object key" % field) from exc
            _closed_json_value(item, "%s.%s" % (field, key))
        return
    raise ProofPlaneError("%s contains a non-JSON value" % field)


def _codex_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _codex_error_code(event: Mapping[str, Any]) -> Optional[str]:
    error = event.get("error")
    candidates = []
    if isinstance(error, Mapping):
        candidates.extend((error.get("code"), error.get("type")))
    candidates.extend((event.get("code"), event.get("error_code")))
    for candidate in candidates:
        if isinstance(candidate, str) and 1 <= len(candidate) <= 128:
            return candidate.strip().lower().replace("-", "_").replace(" ", "_")
    return None


def parse_codex_jsonl(payload: bytes, *, returncode: int, token_limit: int) -> dict[str, Any]:
    """Parse the frozen Codex JSONL protocol without interpreting free text.

    Unknown event kinds, duplicate keys, invalid sequencing, non-finite values,
    and missing usage or final-message evidence are rejected.  A blocked status
    is derived only from a closed machine-readable error-code set; an agent's
    natural-language message can never relabel a run.
    """

    if not isinstance(payload, bytes) or not payload or len(payload) > 20_000_000:
        raise ProofPlaneError("Codex JSONL must be a non-empty bounded byte stream")
    if not isinstance(returncode, int) or isinstance(returncode, bool) or not -255 <= returncode <= 255:
        raise ProofPlaneError("Codex return code is invalid")
    if not isinstance(token_limit, int) or isinstance(token_limit, bool) or not 1 <= token_limit <= 10**9:
        raise ProofPlaneError("Codex token limit is invalid")
    if not payload.endswith(b"\n"):
        raise ProofPlaneError("Codex JSONL is truncated without a terminal newline")

    raw_lines = payload.splitlines(keepends=True)
    if not raw_lines or len(raw_lines) > CODEX_JSONL_EVENT_LIMIT:
        raise ProofPlaneError("Codex JSONL event count is outside the closed limit")
    events = []
    for index, raw_line in enumerate(raw_lines):
        if len(raw_line) > CODEX_JSONL_LINE_LIMIT:
            raise ProofPlaneError("Codex JSONL line exceeds the 1 MB limit")
        if not raw_line.endswith(b"\n") or not raw_line.rstrip(b"\r\n"):
            raise ProofPlaneError("Codex JSONL contains a blank or truncated line")
        try:
            text = raw_line.rstrip(b"\r\n").decode("utf-8", errors="strict")
            event = json.loads(
                text,
                object_pairs_hook=_codex_json_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
            )
        except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise ProofPlaneError("Codex JSONL line %d is invalid" % (index + 1)) from exc
        if not isinstance(event, Mapping):
            raise ProofPlaneError("Codex JSONL events must be objects")
        try:
            _closed_json_value(event, "Codex JSONL line %d" % (index + 1))
        except RecursionError as exc:
            raise ProofPlaneError("Codex JSONL nesting exceeds the closed limit") from exc
        event_type = event.get("type")
        if event_type not in _CODEX_EVENT_TYPES:
            raise ProofPlaneError("Codex JSONL contains an unknown event type")
        events.append(dict(event))

    if events[0].get("type") != "thread.started":
        raise ProofPlaneError("Codex JSONL must begin with thread.started")
    thread_events = [item for item in events if item.get("type") == "thread.started"]
    turn_starts = [item for item in events if item.get("type") == "turn.started"]
    if len(thread_events) != 1 or len(turn_starts) != 1:
        raise ProofPlaneError("Codex JSONL must contain one thread and one turn start")
    thread_id = thread_events[0].get("thread_id")
    if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 512:
        raise ProofPlaneError("Codex thread.started lacks a bounded thread_id")
    turn_start_index = next(index for index, item in enumerate(events) if item.get("type") == "turn.started")
    if turn_start_index != 1:
        raise ProofPlaneError("Codex turn.started must immediately follow thread.started")
    for event in events[2:-1]:
        if event.get("type") in ("thread.started", "turn.started", "turn.completed", "turn.failed"):
            raise ProofPlaneError("Codex JSONL contains an out-of-sequence lifecycle event")

    terminal = events[-1]
    terminal_type = terminal.get("type")
    if terminal_type not in ("turn.completed", "turn.failed", "error"):
        raise ProofPlaneError("Codex JSONL lacks one terminal event")
    final_messages = []
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Codex item.completed lacks an item object")
        if item.get("type") == "agent_message":
            message = item.get("text")
            if not isinstance(message, str) or len(message.encode("utf-8")) > 5_000_000:
                raise ProofPlaneError("Codex final agent message is invalid or oversized")
            final_messages.append(message)

    usage = {"inputTokens": 0, "cachedInputTokens": 0, "outputTokens": 0}
    token_count = 0
    status = "failed"
    reason = "codex-turn-failed"
    complete = False
    error_digest = None
    if terminal_type == "turn.completed":
        raw_usage = terminal.get("usage")
        if not isinstance(raw_usage, Mapping) or set(raw_usage) != {
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
        }:
            raise ProofPlaneError("Codex turn.completed usage fields are invalid")
        numbers = []
        for field in ("input_tokens", "cached_input_tokens", "output_tokens"):
            item = raw_usage[field]
            if not isinstance(item, int) or isinstance(item, bool) or item < 0 or item > 10**9:
                raise ProofPlaneError("Codex token usage is invalid")
            numbers.append(item)
        usage = {
            "inputTokens": numbers[0],
            "cachedInputTokens": numbers[1],
            "outputTokens": numbers[2],
        }
        if numbers[1] > numbers[0]:
            raise ProofPlaneError("Codex cached token usage exceeds total input usage")
        token_count = numbers[0] + numbers[2]
        if not final_messages:
            raise ProofPlaneError("Codex completed without a final agent message")
        if returncode != 0:
            reason = "codex-exit-nonzero"
        elif token_count > token_limit:
            reason = "token-budget-exceeded"
        else:
            status = "completed"
            reason = "turn-completed"
            complete = True
    else:
        error_code = _codex_error_code(terminal)
        error_digest = canonical_digest(terminal)
        if error_code in _BLOCKED_CODEX_ERROR_CODES:
            status = "blocked"
            reason = "codex-" + str(error_code)
        elif terminal_type == "error":
            reason = "codex-error"

    return {
        "terminalStatus": status,
        "reasonCode": reason,
        "complete": complete,
        "truncated": token_count > token_limit,
        "returnCode": returncode,
        "tokenCount": token_count,
        "usage": usage,
        "finalMessage": final_messages[-1] if final_messages else None,
        "threadIdSha256": hashlib.sha256(thread_id.encode("utf-8")).hexdigest(),
        "terminalErrorSha256": error_digest,
        "eventCount": len(events),
    }


def attempt_container_name(run_id: str) -> str:
    if not isinstance(run_id, str) or not run_id or len(run_id) > 500:
        raise ProofPlaneError("runId is invalid")
    return "jstack-model-" + hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:40]


def build_attempt_broker_config(
    *,
    study_id: str,
    run_id: str,
    registration_sha256: str,
    runtime: Path,
    container_name: str,
    uid_gid: str,
    tool_call_limit: int,
    command_timeout_seconds: int,
    ledger_path: Path,
    output_byte_limit: int = 1_000_000,
) -> dict[str, Any]:
    """Build the deterministic, self-bound four-tool broker configuration."""

    value = {
        "schemaVersion": "jstack.proof-broker.config.v1",
        "studyId": study_id,
        "runId": run_id,
        "registrationSha256": registration_sha256,
        "configSha256": "0" * 64,
        "runtimeCommand": str(runtime.resolve()),
        "isolationCommand": "/usr/bin/bwrap",
        "containerId": container_name,
        "workspaceRoot": "/workspace",
        "user": uid_gid,
        "toolCallLimit": tool_call_limit,
        "commandTimeoutSeconds": command_timeout_seconds,
        "outputByteLimit": output_byte_limit,
        "ledgerPath": str(ledger_path.resolve()),
    }
    value["configSha256"] = broker_config_digest(value)
    return validate_broker_config(value)


def model_attempt_artifact_paths(private_root: Path, run_id: str) -> dict[str, Path]:
    """Return raw-content paths kept only in the mode-0700 private store."""

    root = _attempt_path(private_root, run_id, ".artifacts")
    return {
        "root": root,
        "sourceRoot": root / "source",
        "codexHome": root / "codex-home",
        "prompt": root / "prompt.txt",
        "brokerConfig": root / "broker.json",
        "transcript": root / "codex.jsonl",
        "stderr": root / "codex.stderr",
        "patch": root / "candidate.patch",
        "modelResult": root / "model-result.json",
    }


def _exclusive_bytes(path: Path, payload: bytes, *, maximum_bytes: int) -> None:
    if not isinstance(payload, bytes) or len(payload) > maximum_bytes:
        raise ProofPlaneError("private attempt artifact exceeds its closed byte limit")
    atomic_publish_bytes_once(
        path,
        payload,
        mode=0o600,
        maximum_bytes=maximum_bytes,
    )


def _read_regular_bytes(path: Path, field: str, *, maximum_bytes: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute regular non-symlink file" % field)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProofPlaneError("%s could not be opened safely" % field) from exc
    chunks = []
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise ProofPlaneError("%s is not a bounded regular file" % field)
        while True:
            chunk = os.read(descriptor, min(128 * 1024, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ProofPlaneError("%s exceeds its closed byte limit" % field)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            getattr(before, "st_mtime_ns", int(before.st_mtime * 1_000_000_000)),
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
        ):
            raise ProofPlaneError("%s changed while it was being read" % field)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _bound_text_file(path: Path, expected_sha256: str, field: str, *, maximum_bytes: int = 500_000) -> bytes:
    payload = _read_regular_bytes(path, field, maximum_bytes=maximum_bytes)
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ProofPlaneError("%s digest or byte limit differs from the frozen binding" % field)
    try:
        payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ProofPlaneError("%s must be UTF-8" % field) from exc
    if b"\x00" in payload:
        raise ProofPlaneError("%s contains a NUL byte" % field)
    return payload


def compose_model_prompt(protocol: bytes, brief: bytes) -> bytes:
    if not isinstance(protocol, bytes) or not isinstance(brief, bytes):
        raise ProofPlaneError("condition protocol and task brief must be bytes")
    prompt = (
        protocol.rstrip(b"\r\n")
        + b"\n\n--- BEGIN REGISTERED TASK BRIEF ---\n\n"
        + brief.rstrip(b"\r\n")
        + b"\n\n--- END REGISTERED TASK BRIEF ---\n"
    )
    if not prompt or len(prompt) > 1_000_000:
        raise ProofPlaneError("composed model prompt exceeds the 1 MB bound")
    return prompt


def _validate_attempt_binding(
    expected_run: Mapping[str, Any],
    task: Mapping[str, Any],
    registration: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        normalized_task = validate_task(task)
    except ContractError as exc:
        raise ProofPlaneError("model attempt task is invalid: %s" % exc) from exc
    required_run_fields = {
        "runId",
        "pairId",
        "taskId",
        "taskDigest",
        "family",
        "taskKind",
        "condition",
        "mode",
        "repetition",
        "evidenceClass",
        "hostSha256",
        "environmentSha256",
        "limitsSha256",
        "baselineCommit",
        "hiddenTestBundleSha256",
    }
    if not isinstance(expected_run, Mapping) or set(expected_run) != required_run_fields:
        raise ProofPlaneError("expected run fields do not match the frozen plan")
    condition = expected_run["condition"]
    mode = expected_run["mode"]
    if condition not in ("plain", "jstack") or mode not in ("controlled", "operational"):
        raise ProofPlaneError("expected run condition or mode is invalid")
    repetition = expected_run["repetition"]
    expected_pair_id = "%s:%s:r%s" % (normalized_task["taskId"], mode, repetition)
    if (
        not isinstance(repetition, int)
        or isinstance(repetition, bool)
        or not 1 <= repetition <= 3
        or expected_run["pairId"] != expected_pair_id
        or expected_run["runId"] != "%s:%s" % (expected_pair_id, condition)
    ):
        raise ProofPlaneError("expected run ID, pair, or repetition differs from the frozen plan")
    try:
        limits = registration["modes"][mode]["conditions"][condition]
        environment_digest = canonical_digest(
            {
                "imageDigest": normalized_task["environment"]["imageDigest"],
                "toolVersionsDigest": canonical_digest(normalized_task["environment"]["toolVersions"]),
            }
        )
        comparisons = {
            "taskId": normalized_task["taskId"],
            "taskDigest": canonical_digest(normalized_task),
            "family": normalized_task["family"],
            "taskKind": normalized_task["taskKind"],
            "evidenceClass": "public",
            "hostSha256": canonical_digest(registration["host"]),
            "environmentSha256": environment_digest,
            "limitsSha256": canonical_digest(
                {
                    field: limits[field]
                    for field in (
                        "wallClockSeconds",
                        "tokenLimit",
                        "costUsd",
                        "toolCallLimit",
                        "allowedToolsDigest",
                    )
                }
            ),
            "baselineCommit": normalized_task["baseline"]["commit"],
            "hiddenTestBundleSha256": normalized_task["holdout"]["hiddenTestBundleSha256"],
        }
    except (KeyError, TypeError) as exc:
        raise ProofPlaneError("registration lacks the selected run binding") from exc
    if any(expected_run.get(field) != value for field, value in comparisons.items()):
        raise ProofPlaneError("task, host, environment, or limit binding differs from the expected run")
    if normalized_task["source"]["upstreamCommit"] != normalized_task["baseline"]["commit"]:
        raise ProofPlaneError("task source and baseline commits differ")
    return normalized_task, dict(limits)


def _absolute_executable(path: Path, field: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or not os.access(path, os.X_OK)
    ):
        raise ProofPlaneError("%s must be an absolute regular non-symlink executable" % field)
    return path.resolve()


def _registration_path_in_tag(registration_path: Path, repo_root: Path) -> None:
    """Require the registration itself to be one tracked blob in tagged HEAD."""

    if (
        not isinstance(registration_path, Path)
        or not registration_path.is_absolute()
        or registration_path.is_symlink()
        or not registration_path.is_file()
    ):
        raise ProofPlaneError("registration_path must be an absolute regular non-symlink file")
    try:
        relative = registration_path.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise ProofPlaneError("registration_path must be inside the registered repository") from exc
    resolved = resolve_within(repo_root, relative, "study registration")
    if resolved != registration_path.resolve():
        raise ProofPlaneError("registration_path does not resolve to its tagged repository file")
    tracked = _git_output(repo_root, ["ls-files", "--error-unmatch", "--", relative])
    if tracked != relative:
        raise ProofPlaneError("study registration is not one exact tracked file")
    tagged_blob = _git_output(repo_root, ["rev-parse", "HEAD:" + relative])
    local_blob = _git_output(repo_root, ["hash-object", "--", str(registration_path)])
    if tagged_blob != local_blob:
        raise ProofPlaneError("study registration differs from its tagged Git blob")


def _planned_attempt_evidence_paths(private_root: Path, run_id: str) -> dict[str, Path]:
    """Return attempt paths without creating directories during admission."""

    start = _attempt_path(private_root, run_id, ".start.json")
    slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    return {
        "start": start,
        "terminal": start.with_name(slug + ".terminal.json"),
        "ledger": private_root / "ledgers" / (slug + ".jsonl"),
        "anchor": private_root / "anchors" / (slug + ".anchor.json"),
    }


def planned_attempt_evidence_paths(private_root: Path, run_id: str) -> dict[str, Path]:
    """Expose deterministic preregistration paths without creating them."""

    return _planned_attempt_evidence_paths(private_root, run_id)


def _container_absence_proven(runtime: Path, container_name: str) -> bool:
    """Independently prove an exact Apple-container ID is absent.

    Cleanup return codes are not destruction proof.  The machine-readable
    ``list --all`` result is accepted only in the documented array shape and
    only when every entry exposes one ``configuration.id`` string.
    """

    result = _run(
        [str(runtime), "list", "--all", "--format", "json"],
        timeout=30,
        maximum_output=2_000_000,
    )
    if result.returncode != 0 or result.stderr:
        return False
    try:
        value = json.loads(
            result.stdout.decode("utf-8", errors="strict"),
            object_pairs_hook=_codex_json_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError("non-finite JSON number %s" % item)
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError, ProofPlaneError):
        return False
    if not isinstance(value, list):
        return False
    observed = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            return False
        configuration = item.get("configuration")
        if not isinstance(configuration, Mapping):
            return False
        identifier = configuration.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 128:
            return False
        observed.append(identifier)
    return container_name not in observed


def _preflight_binding_view_for_attempt(
    *,
    registration: Mapping[str, Any],
    registration_sha256: str,
    manifest_sha256: str,
    evidence_bindings_sha256: str,
    schedule_sha256: str,
    git_binding: Mapping[str, Any],
    codex_version: str,
    codex_provenance: str,
    tool_surface: Mapping[str, Any],
    qualification_set: Mapping[str, Any],
    qualification_digests: Mapping[str, str],
    task_artifact_set_summary: Mapping[str, Any],
) -> dict[str, Any]:
    qualification_binding = {
        "digestEncoding": CANONICAL_FILE_DIGEST_ENCODING,
        "receiptSetRawSha256": qualification_digests["rawCanonicalFileSha256"],
        "receiptSetCanonicalSha256": qualification_digests["canonicalDocumentSha256"],
        "receiptSetSelfSha256": qualification_digests["selfSha256"],
        "commandMapSha256": qualification_set["commandMapSha256"],
        "qualifiedTaskCount": qualification_set["qualifiedTaskCount"],
        "sealedAt": qualification_set["sealedAt"],
        "imageBuilderAttestation": image_builder_attestation_summary(
            qualification_set["imageBuilderAttestation"],
            expected_task_ids=tuple(
                sorted(item["taskId"] for item in qualification_set["results"])
            ),
        ),
    }
    return {
        "studyId": registration["studyId"],
        "registrationSha256": registration_sha256,
        "manifestSha256": manifest_sha256,
        "evidenceBindingsSha256": evidence_bindings_sha256,
        "executionScheduleSha256": schedule_sha256,
        "registrationTag": {
            "reference": registration["registrationRef"],
            "objectFormat": "sha1",
            "tagObject": git_binding["tagObject"],
            "commit": git_binding["commit"],
        },
        "harnessLock": {
            "path": registration["executor"]["harnessLockPath"],
            "sha256": registration["executor"]["harnessLockSha256"],
        },
        "runtime": {
            "name": "apple-container",
            "version": registration["executor"]["version"],
            "binarySha256": registration["executor"]["runtimeSha256"],
        },
        "runtimeTcb": validate_runtime_tcb_summary(
            registration["executor"]["runtimeTcb"],
            "registered executor runtimeTcb",
        ),
        "codex": {
            "version": codex_version,
            "binarySha256": registration["executor"]["codexCliBinarySha256"],
            "provenance": codex_provenance,
        },
        "toolSurface": dict(tool_surface),
        "qualification": qualification_binding,
        "taskArtifacts": dict(task_artifact_set_summary),
    }


def _load_trusted_attempt_admission(
    *,
    run_id: str,
    registration_path: Path,
    expected_run_set_path: Path,
    preflight_receipt_path: Path,
    qualification_receipt_set_path: Path,
    task_artifact_set_summary_path: Path,
    repo_root: Path,
    artifact_root: Path,
    private_root: Path,
    runtime: Path,
    codex_path: Path,
    require_unstarted: bool = True,
) -> dict[str, Any]:
    """Derive one attempt solely from cross-bound, frozen study artifacts.

    This is the only admission path used by :func:`run_model_attempt`.  It is
    deliberately side-effect free: no attempt directory, ledger, receipt, or
    model artifact is created until every artifact and live immutable binding
    below has passed.
    """

    if not isinstance(require_unstarted, bool):
        raise ProofPlaneError("require_unstarted must be boolean")
    if not isinstance(run_id, str) or not run_id or run_id != run_id.strip() or len(run_id) > 500:
        raise ProofPlaneError("run_id must be one bounded frozen run identifier")
    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("repo_root must be an absolute regular non-symlink directory")
    repo_root = repo_root.resolve()
    artifact_root = _verify_private_root(artifact_root, "artifact_root")
    private_root = _verify_private_root(private_root, "private_root")
    if artifact_root != private_root / "task-artifacts":
        raise ProofPlaneError(
            "artifact_root must use the fixed private task-artifacts path"
        )
    fixed_task_artifact_set_summary_path(
        private_root, task_artifact_set_summary_path
    )
    runtime = _absolute_executable(runtime, "runtime")
    codex_path = _absolute_executable(codex_path, "codex_path")
    for path, field in (
        (expected_run_set_path, "expected_run_set_path"),
        (preflight_receipt_path, "preflight_receipt_path"),
        (qualification_receipt_set_path, "qualification_receipt_set_path"),
    ):
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
        ):
            raise ProofPlaneError("%s must be an absolute regular non-symlink file" % field)
    _registration_path_in_tag(registration_path, repo_root)

    bundle = validate_bundle(registration_path, repo_root=repo_root)
    registration = validate_registration(load_json(registration_path), repo_root=repo_root)
    registration_sha256 = canonical_digest(registration)
    if registration_sha256 != bundle["registrationSha256"]:
        raise ProofPlaneError("registration changed while trusted admission was loading")
    manifest_path = resolve_within(repo_root, registration["manifestPath"], "study manifest")
    try:
        manifest = validate_manifest(load_json(manifest_path))
    except ContractError as exc:
        raise ProofPlaneError("study manifest is invalid: %s" % exc) from exc
    manifest_sha256 = canonical_digest(manifest)
    expected_set = load_canonical_expected_run_set(expected_run_set_path)
    registered_runtime_tcb = validate_runtime_tcb_summary(
        registration["executor"]["runtimeTcb"],
        "registered executor runtimeTcb",
    )
    schedule = execution_schedule(
        manifest["executionPlan"]["expectedRuns"],
        registration["schedule"]["seedSha256"],
    )
    schedule_sha256 = canonical_digest(schedule)
    immutable_expected = {
        "studyId": registration["studyId"],
        "registrationSha256": registration_sha256,
        "manifestSha256": manifest_sha256,
        "scheduleSha256": schedule_sha256,
        "harnessLockSha256": registration["executor"]["harnessLockSha256"],
        "qualificationReceiptSetSha256": registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        "qualificationCommandMapSha256": registration["executor"][
            "isolationQualificationCommandSha256"
        ],
        "runtimeTcbSha256": registered_runtime_tcb["tcbSha256"],
    }
    if any(expected_set.get(field) != value for field, value in immutable_expected.items()):
        raise ProofPlaneError("expected-run set differs from the registered study artifacts")
    if expected_set["expectedRuns"] != manifest["executionPlan"]["expectedRuns"]:
        raise ProofPlaneError("expected-run set does not exactly equal the registered manifest plan")
    expected_by_run = {item["runId"]: item for item in expected_set["expectedRuns"]}
    if run_id not in expected_by_run:
        raise ProofPlaneError("run_id is absent from the frozen expected-run set")
    expected_run = expected_by_run[run_id]
    scheduled = {item["runId"]: item for item in schedule}
    if run_id not in scheduled:
        raise ProofPlaneError("run_id is absent from the frozen execution schedule")
    ordinal = scheduled[run_id]["ordinal"]

    tasks: dict[str, dict[str, Any]] = {}
    task_entries: dict[str, tuple[Mapping[str, Any], Path]] = {}
    for index, relative in enumerate(manifest["taskFiles"]):
        task_path = resolve_within(repo_root, relative, "manifest task[%d]" % index)
        try:
            task = validate_task(load_json(task_path))
        except ContractError as exc:
            raise ProofPlaneError("manifest task[%d] is invalid: %s" % (index, exc)) from exc
        if task["taskId"] in tasks:
            raise ProofPlaneError("manifest contains a duplicate taskId")
        tasks[task["taskId"]] = task
        task_entries[task["taskId"]] = (task, task_path)
    if set(tasks) != {item["taskId"] for item in expected_set["expectedRuns"]}:
        raise ProofPlaneError("manifest task set differs from the frozen run matrix")
    task = tasks[expected_run["taskId"]]
    normalized_task, limits = _validate_attempt_binding(expected_run, task, registration)

    task_artifacts = load_canonical_task_artifact_set_summary(
        task_artifact_set_summary_path,
        expected_task_ids=tuple(sorted(tasks)),
    )
    artifact_rows, registered_rows = _task_artifact_summary_rows(task_entries)
    task_artifacts = validate_task_artifact_summary_bindings(
        task_artifacts,
        study_id=registration["studyId"],
        artifact_rows=artifact_rows,
        registered_task_rows=registered_rows,
    )
    task_artifact_digests = task_artifact_set_summary_digests(
        task_artifacts, expected_task_ids=tuple(sorted(tasks))
    )
    if (
        expected_set["taskArtifactSetSummarySha256"]
        != task_artifact_digests["selfSha256"]
        or expected_set["taskArtifactSetSummaryRawSha256"]
        != task_artifact_digests["rawCanonicalFileSha256"]
    ):
        raise ProofPlaneError(
            "task-artifact summary differs from the frozen expected-run set"
        )

    evidence_path = resolve_within(
        repo_root,
        registration["evidencePlan"]["bindingsPath"],
        "study evidence bindings",
    )
    evidence_bindings_sha256 = file_digest(evidence_path)
    if evidence_bindings_sha256 != expected_set["evidenceBindingsSha256"]:
        raise ProofPlaneError("evidence bindings differ from the frozen expected-run set")
    evidence_bindings = validate_evidence_bindings(
        load_json(evidence_path),
        study_id=registration["studyId"],
        expected_runs=expected_set["expectedRuns"],
    )
    for task_id, task_document in tasks.items():
        if evidence_bindings["imageSha256ByTask"][task_id] != task_document["environment"]["imageDigest"]:
            raise ProofPlaneError("evidence image binding differs for task %s" % task_id)
    for mode in ("controlled", "operational"):
        for condition in ("plain", "jstack"):
            cell = "%s:%s" % (mode, condition)
            registered_cell = registration["modes"][mode]["conditions"][condition]
            if evidence_bindings["conditionSha256ByCell"][cell] != canonical_digest(registered_cell):
                raise ProofPlaneError("evidence condition binding differs for cell %s" % cell)

    task_ids = tuple(sorted(tasks))
    qualification_set = load_canonical_qualification_receipt_set(
        qualification_receipt_set_path,
        expected_task_ids=task_ids,
        registered_receipt_set_sha256=registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        registered_command_map_sha256=registration["executor"][
            "isolationQualificationCommandSha256"
        ],
    )
    qualification_digests = qualification_receipt_set_digests(
        qualification_set,
        expected_task_ids=task_ids,
    )
    if (
        qualification_digests["rawCanonicalFileSha256"]
        != expected_set["qualificationReceiptSetSha256"]
        or qualification_set["commandMapSha256"]
        != expected_set["qualificationCommandMapSha256"]
    ):
        raise ProofPlaneError("qualification receipt set differs from the frozen expected-run set")
    qualification_by_task = {item["taskId"]: item for item in qualification_set["results"]}
    qualified_builder_attestation = image_builder_attestation_summary(
        qualification_set["imageBuilderAttestation"],
        expected_task_ids=task_ids,
    )
    if (
        qualified_builder_attestation
        != registration["executor"]["imageBuilderAttestation"]
    ):
        raise ProofPlaneError(
            "qualification image-builder attestation differs from the registration"
        )
    expected_identity = qualification_set["identity"]
    uid_gid = "%d:%d" % (expected_identity["uid"], expected_identity["gid"])
    expected_runtime = {
        "name": "apple-container",
        "version": registration["executor"]["version"],
        "binarySha256": registration["executor"]["runtimeSha256"],
    }
    if qualification_set["runtime"] != expected_runtime:
        raise ProofPlaneError("qualification runtime differs from the registered executor")
    qualified_runtime_tcb = validate_apple_container_tcb_document(
        qualification_set["runtimeTcb"]
    )
    qualified_runtime_tcb_summary = runtime_tcb_summary(qualified_runtime_tcb)
    if qualified_runtime_tcb_summary != registered_runtime_tcb:
        raise ProofPlaneError(
            "qualification runtime TCB differs from the registered executor"
        )
    if expected_set["runtimeTcbSha256"] != qualified_runtime_tcb_summary["tcbSha256"]:
        raise ProofPlaneError(
            "qualification runtime TCB differs from the frozen expected-run set"
        )
    for task_id, task_document in tasks.items():
        result = qualification_by_task[task_id]
        task_tools = task_document["environment"]["toolVersions"]
        _sha256(
            task_tools.get("source-content-sha256"),
            "task %s source content digest" % task_id,
        )
        if result["studyId"] != registration["studyId"] or result["identity"] != expected_identity:
            raise ProofPlaneError("task %s qualification identity or study binding differs" % task_id)
        if result["runtime"] != expected_runtime or result["image"] != {
            "reference": task_document["environment"]["imageReference"],
            "digest": task_document["environment"]["imageDigest"],
        }:
            raise ProofPlaneError("task %s qualification runtime or image binding differs" % task_id)
        if result["imageEvidence"] != {
            "imageBuildManifestSha256": task_tools[
                "image-build-manifest-sha256"
            ],
            "imageBuildReceiptSha256": task_tools["image-build-receipt-sha256"],
            "imageArtifactInspectionReceiptSha256": task_tools[
                "image-artifact-inspection-receipt-sha256"
            ],
        }:
            raise ProofPlaneError(
                "task %s qualification image-evidence binding differs" % task_id
            )
        if any(task_tools.get(name) != version for name, version in result["qualifiedToolVersions"].items()):
            raise ProofPlaneError("task %s qualified tool versions differ from its descriptor" % task_id)
        if task_tools.get("image-qualification-result-sha256") != qualification_set[
            "resultFileSha256ByTask"
        ][task_id]:
            raise ProofPlaneError("task %s qualification-result file digest differs" % task_id)
        if result["canary"]["policySha256"] != registration["executor"]["policySha256"]:
            raise ProofPlaneError("task %s qualification policy differs from the executor" % task_id)

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ProofPlaneError("Beta1 executor requires Apple silicon macOS")
    if file_digest(runtime) != registration["executor"]["runtimeSha256"]:
        raise ProofPlaneError("runtime binary differs from the frozen registration")
    runtime_version_result = _run([str(runtime), "--version"], timeout=15, maximum_output=100_000)
    runtime_version_text = (runtime_version_result.stdout + runtime_version_result.stderr).decode(
        "utf-8", errors="replace"
    )
    if (
        runtime_version_result.returncode != 0
        or _version_tuple(runtime_version_text) != _version_tuple(registration["executor"]["version"])
        or _version_tuple(registration["executor"]["version"]) < RUNTIME_MINIMUM
    ):
        raise ProofPlaneError("runtime version differs from the frozen registration")
    admission_runtime_tcb = _inspect_exact_runtime_tcb(
        runtime,
        qualified_runtime_tcb,
        "trusted-admission live runtime TCB",
    )
    if admission_runtime_tcb.tcb_sha256 != expected_set["runtimeTcbSha256"]:
        raise ProofPlaneError(
            "trusted-admission live runtime TCB differs from the frozen expected-run set"
        )
    selected_qualification = qualification_by_task[normalized_task["taskId"]]
    qualified_image_store = validate_local_image_store_observation(
        selected_qualification["imageAliasVerification"]["storeAfter"],
        image_reference=normalized_task["environment"]["imageReference"],
        image_digest=normalized_task["environment"]["imageDigest"],
        field="trusted-admission qualified image-store observation",
    )
    admission_image_store = inspect_local_image_store(
        runtime,
        admission_runtime_tcb.document,
        normalized_task["environment"]["imageReference"],
        normalized_task["environment"]["imageDigest"],
    )
    if admission_image_store != qualified_image_store:
        raise ProofPlaneError(
            "trusted-admission live image store differs from qualification"
        )
    if file_digest(codex_path) != registration["executor"]["codexCliBinarySha256"]:
        raise ProofPlaneError("Codex CLI binary differs from the frozen registration")
    codex_provenance = codex_cli_provenance(codex_path)
    if codex_provenance != registration["executor"]["codexCliProvenance"]:
        raise ProofPlaneError("Codex CLI signing provenance differs from the frozen registration")
    codex_version = "%s %s" % (registration["host"]["name"], registration["host"]["version"])
    codex_version_result = _run([str(codex_path), "--version"], timeout=15, maximum_output=100_000)
    if (
        codex_version_result.returncode != 0
        or codex_version_result.stderr
        or codex_version_result.stdout.decode("utf-8", errors="strict").strip() != codex_version
    ):
        raise ProofPlaneError("Codex CLI version differs from the frozen host binding")

    git_binding = verify_registration_ref(registration, repo_root)
    if (
        git_binding["tagObject"] != expected_set["registrationTagObjectSha1"]
        or git_binding["commit"] != expected_set["registrationCommitSha1"]
    ):
        raise ProofPlaneError("live registration tag differs from the frozen expected-run set")
    server = resolve_within(
        repo_root,
        registration["executor"]["jstackMcpServerPath"],
        "JStack MCP server",
    )
    if file_digest(server) != registration["executor"]["jstackMcpServerSha256"]:
        raise ProofPlaneError("JStack MCP server differs from the frozen registration")
    surface = probe_mcp_tool_surface(
        [str(Path(shutil.which("python3") or "/usr/bin/python3").resolve()), str(server)],
        expected_count=registration["executor"]["jstackMcpToolCount"],
        name_prefix="jstack_",
        expected_version=registration["targetJStackVersion"],
    )
    if surface["toolsSha256"] != registration["executor"]["jstackMcpToolsSha256"]:
        raise ProofPlaneError("JStack MCP tool surface differs from the frozen registration")
    proof_tools_sha256 = canonical_digest(proof_tool_descriptors())
    for mode in ("controlled", "operational"):
        for condition in ("plain", "jstack"):
            if registration["modes"][mode]["conditions"][condition][
                "proofBrokerToolsDigest"
            ] != proof_tools_sha256:
                raise ProofPlaneError("proof-broker tool surface differs from the frozen registration")
    tool_surface_body = {
        "proofBrokerToolsSha256": proof_tools_sha256,
        "proofBrokerToolCount": len(PROOF_TOOLS),
        "jstackMcpServerSha256": registration["executor"]["jstackMcpServerSha256"],
        "jstackMcpToolsSha256": surface["toolsSha256"],
        "jstackMcpToolCount": surface["count"],
    }
    tool_surface = {**tool_surface_body, "combinedSha256": canonical_digest(tool_surface_body)}
    preflight_bindings = _preflight_binding_view_for_attempt(
        registration=registration,
        registration_sha256=registration_sha256,
        manifest_sha256=manifest_sha256,
        evidence_bindings_sha256=evidence_bindings_sha256,
        schedule_sha256=schedule_sha256,
        git_binding=git_binding,
        codex_version=codex_version,
        codex_provenance=codex_provenance,
        tool_surface=tool_surface,
        qualification_set=qualification_set,
        qualification_digests=qualification_digests,
        task_artifact_set_summary=task_artifacts,
    )
    preflight_receipt = load_canonical_preflight_receipt(
        preflight_receipt_path,
        expected_bindings=preflight_bindings,
        expected_file_sha256=expected_set["preflightReceiptRawSha256"],
    )
    if (
        preflight_receipt["preflightReceiptSha256"] != expected_set["preflightReceiptSha256"]
        or preflight_receipt["modelExecutionAllowed"] is not True
    ):
        raise ProofPlaneError("preflight receipt does not authorize this frozen expected-run set")
    preflight_time = dt.datetime.fromisoformat(preflight_receipt["checkedAt"].replace("Z", "+00:00"))
    frozen_time = dt.datetime.fromisoformat(expected_set["frozenAt"].replace("Z", "+00:00"))
    if preflight_time > frozen_time or frozen_time > dt.datetime.now(dt.timezone.utc):
        raise ProofPlaneError("expected-run set chronology does not admit model execution")

    source_root = resolve_within(artifact_root, normalized_task["taskId"], "private task artifact")
    if source_root.is_symlink() or not source_root.is_dir():
        raise ProofPlaneError("private task artifact directory is missing")
    source_archive = resolve_within(source_root, "source.tar", "private source archive")
    if file_digest(source_archive) != normalized_task["source"]["sourceArchiveSha256"]:
        raise ProofPlaneError("private source archive differs from the frozen task descriptor")
    protocol_path = resolve_within(
        repo_root,
        registration["conditions"][expected_run["condition"]]["protocolPath"],
        "condition protocol",
    )
    brief_path = resolve_within(repo_root, normalized_task["brief"]["path"], "task brief")
    protocol = _bound_text_file(
        protocol_path,
        registration["conditions"][expected_run["condition"]]["protocolSha256"],
        "condition protocol",
    )
    brief = _bound_text_file(brief_path, normalized_task["brief"]["sha256"], "task brief")
    prompt = compose_model_prompt(protocol, brief)

    planned_evidence = _planned_attempt_evidence_paths(private_root, run_id)
    broker_config = build_attempt_broker_config(
        study_id=registration["studyId"],
        run_id=run_id,
        registration_sha256=registration_sha256,
        runtime=runtime,
        container_name=attempt_container_name(run_id),
        uid_gid=uid_gid,
        tool_call_limit=int(limits["toolCallLimit"]),
        command_timeout_seconds=min(int(limits["wallClockSeconds"]), 3600),
        ledger_path=planned_evidence["ledger"],
    )
    if broker_config["configSha256"] != evidence_bindings["configSha256ByRun"][run_id]:
        raise ProofPlaneError("proof broker configuration differs from the frozen evidence binding")
    artifact_paths = model_attempt_artifact_paths(private_root, run_id)
    if require_unstarted:
        for path in (artifact_paths["root"], *planned_evidence.values()):
            if path.exists() or path.is_symlink():
                raise ProofPlaneError("private model-attempt artifacts already exist; retries are forbidden")

    return {
        "runId": run_id,
        "ordinal": ordinal,
        "expectedRun": expected_run,
        "task": normalized_task,
        "limits": limits,
        "registration": registration,
        "registrationSha256": registration_sha256,
        "scheduleSha256": schedule_sha256,
        "expectedRunSetSha256": expected_set["expectedRunSetSha256"],
        "preflightReceiptSha256": preflight_receipt["preflightReceiptSha256"],
        "qualificationReceiptSetSha256": qualification_digests["rawCanonicalFileSha256"],
        "qualification": qualification_by_task[normalized_task["taskId"]],
        "runtimeTcb": qualified_runtime_tcb,
        "runtimeTcbSha256": qualified_runtime_tcb_summary["tcbSha256"],
        "imageStoreObservation": admission_image_store,
        "uidGid": uid_gid,
        "sourceArchive": source_archive,
        "prompt": prompt,
        "brokerConfig": broker_config,
        "surface": surface,
        "server": server,
        "artifactPaths": artifact_paths,
    }


def validate_frozen_study_admission(
    *,
    registration_path: Path,
    expected_run_set_path: Path,
    preflight_receipt_path: Path,
    qualification_receipt_set_path: Path,
    task_artifact_set_summary_path: Path,
    repo_root: Path,
    artifact_root: Path,
    private_root: Path,
    runtime: Path,
    codex_path: Path,
) -> dict[str, Any]:
    """Revalidate the immutable whole-study admission without starting a run.

    The expected-run document is validated first and selects its own first
    frozen run identifier.  The trusted attempt loader then replays every
    set-wide, registration, runtime, tool-surface, qualification, image-store,
    task-artifact, and preflight join.  It creates no attempt state and accepts
    no caller-selected run identifier.
    """

    expected_set = load_canonical_expected_run_set(expected_run_set_path)
    expected_runs = expected_set["expectedRuns"]
    if len(expected_runs) != 216:
        raise ProofPlaneError("frozen admission must contain exactly 216 expected runs")
    first = expected_runs[0]
    if not isinstance(first, Mapping) or not isinstance(first.get("runId"), str):
        raise ProofPlaneError("frozen admission first run identifier is invalid")
    admission = _load_trusted_attempt_admission(
        run_id=first["runId"],
        registration_path=registration_path,
        expected_run_set_path=expected_run_set_path,
        preflight_receipt_path=preflight_receipt_path,
        qualification_receipt_set_path=qualification_receipt_set_path,
        task_artifact_set_summary_path=task_artifact_set_summary_path,
        repo_root=repo_root,
        artifact_root=artifact_root,
        private_root=private_root,
        runtime=runtime,
        codex_path=codex_path,
        require_unstarted=False,
    )
    return {
        "schemaVersion": "jstack.eval.frozen-study-admission-validation.v1",
        "studyId": admission["registration"]["studyId"],
        "expectedRunCount": len(expected_runs),
        "firstRunId": first["runId"],
        "registrationSha256": admission["registrationSha256"],
        "expectedRunSetSha256": admission["expectedRunSetSha256"],
        "preflightReceiptSha256": admission["preflightReceiptSha256"],
        "runtimeTcbSha256": admission["runtimeTcb"]["tcbSha256"],
        "mutated": False,
    }


def _retain_private_bytes_once_or_equal(
    path: Path,
    payload: bytes,
    *,
    field: str,
    maximum_bytes: int,
) -> None:
    """Publish one retained artifact, or accept only its identical prior bytes.

    This is used solely inside one already-started attempt.  It permits the
    finalizer to retain evidence after an earlier step in the same process
    published the prompt or broker configuration, while still refusing every
    substitution and every cross-process retry.
    """

    if path.exists() or path.is_symlink():
        if _read_regular_bytes(path, field, maximum_bytes=maximum_bytes) != payload:
            raise ProofPlaneError("existing %s differs from the retained attempt" % field)
        return
    _exclusive_bytes(path, payload, maximum_bytes=maximum_bytes)


def _prepare_attempt_directories(artifacts: Mapping[str, Path]) -> None:
    root = artifacts["root"]
    _ensure_private_directory(root.parent, "attempts")
    if not root.exists():
        root.mkdir(mode=0o700)
    if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ProofPlaneError("private model-attempt artifact root is unsafe")
    for directory, field in (
        (artifacts["sourceRoot"], "attempt source"),
        (artifacts["codexHome"], "attempt Codex home"),
    ):
        if not directory.exists():
            directory.mkdir(mode=0o700)
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or stat.S_IMODE(directory.stat().st_mode) & 0o077
        ):
            raise ProofPlaneError("%s directory is unsafe" % field)


def _prevalidate_attempt_artifacts(
    *,
    artifacts: Mapping[str, Path],
    prompt: bytes,
    broker_config: Mapping[str, Any],
    model_result: Mapping[str, Any],
    trusted_attempt_plan: TrustedAttemptPlan,
) -> None:
    """Validate every non-terminal member before terminal publication.

    ``validate_attempt_bundle`` remains the authoritative whole-bundle check,
    but it necessarily requires the terminal itself.  This pre-publication
    boundary closes the dangerous gap in which malformed raw artifacts could
    otherwise cause a write-once terminal to be published and only then fail.
    """

    root = artifacts["root"]
    if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ProofPlaneError("attempt artifact root is not private")
    observed = {child.name for child in root.iterdir()}
    if observed != ARTIFACT_ENTRY_NAMES:
        raise ProofPlaneError("attempt artifact set is incomplete or contains extras")
    for directory, field in (
        (artifacts["sourceRoot"], "attempt source"),
        (artifacts["codexHome"], "attempt Codex home"),
    ):
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or stat.S_IMODE(directory.stat().st_mode) & 0o077
        ):
            raise ProofPlaneError("%s directory is not private" % field)
    raw = {
        key: _read_regular_bytes(
            artifacts[key],
            "attempt %s" % key,
            maximum_bytes=ARTIFACT_FILE_LIMITS[
                "broker_config" if key == "brokerConfig" else "model_result" if key == "modelResult" else key
            ],
        )
        for key in (
            "prompt",
            "brokerConfig",
            "transcript",
            "stderr",
            "patch",
            "modelResult",
        )
    }
    for key in ("prompt", "brokerConfig", "transcript", "stderr", "patch", "modelResult"):
        shape = artifacts[key].stat()
        if not stat.S_ISREG(shape.st_mode) or stat.S_IMODE(shape.st_mode) & 0o077:
            raise ProofPlaneError("attempt %s is not a private regular file" % key)
    if raw["prompt"] != prompt:
        raise ProofPlaneError("attempt prompt differs from its trusted bytes")
    expected_broker_raw = (
        json.dumps(
            dict(broker_config),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    expected_model_raw = (
        json.dumps(
            dict(model_result),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if raw["brokerConfig"] != expected_broker_raw:
        raise ProofPlaneError("attempt broker configuration differs from its trusted value")
    if raw["modelResult"] != expected_model_raw:
        raise ProofPlaneError("attempt model result differs from its validated value")
    actual = {
        "promptSha256": hashlib.sha256(raw["prompt"]).hexdigest(),
        "brokerConfigSha256": broker_config["configSha256"],
        "commandSha256": model_result["commandSha256"],
        "modelInstanceIdSha256": model_result["modelInstanceIdSha256"],
        "sourceArchiveSha256": model_result["sourceArchiveSha256"],
        "sourceContentSha256": model_result["sourceContentSha256"],
        "baselineCommit": model_result["baselineCommit"],
        "baselineResultSha256": trusted_attempt_plan.baseline_result_sha256,
        "runtimeTcbSha256": model_result["runtimeTcbObservation"][
            "expectedSha256"
        ],
        "imageStoreObservationSha256": model_result["imageStoreObservation"][
            "expectedSha256"
        ],
    }
    if actual != trusted_attempt_plan.as_dict():
        raise ProofPlaneError("attempt artifacts differ from the trusted attempt plan")
    artifact_digests = {
        "transcriptSha256": hashlib.sha256(raw["transcript"]).hexdigest(),
        "stderrSha256": hashlib.sha256(raw["stderr"]).hexdigest(),
        "patchSha256": hashlib.sha256(raw["patch"]).hexdigest(),
    }
    if any(model_result[field] != digest for field, digest in artifact_digests.items()):
        raise ProofPlaneError("model result differs from retained raw artifacts")


def reconcile_consumed_attempt(
    *,
    controller: StudyRunController,
    reservation: ReservationHandle,
) -> dict[str, Any]:
    """Record a complete terminal left behind by an interrupted controller call.

    This recovery path never launches, deletes, or otherwise touches a model
    VM.  It is deliberately limited to the crash window after a complete
    terminal bundle was already published.  A start with missing destruction,
    patch, model-result, or terminal evidence remains ``recovery-required`` and
    cannot be converted into a terminal by assertion or by retrying the model.
    """

    if type(controller) is not StudyRunController:
        raise ProofPlaneError("controller must be one concrete StudyRunController")
    if not isinstance(reservation, ReservationHandle):
        raise ProofPlaneError("reservation must be returned by StudyRunController.reserve_next")
    state = controller.status()
    active = {
        item["runId"]: item
        for item in state.get("active", [])
        if isinstance(item, Mapping) and isinstance(item.get("runId"), str)
    }
    lifecycle = active.get(reservation.run_id)
    if lifecycle is None or lifecycle.get("reservationEntrySha256") != (
        reservation.reservation_entry_sha256
    ):
        raise ProofPlaneError("reservation is not the active consumed attempt")
    if "startReceiptSha256" not in lifecycle:
        raise ProofPlaneError("reservation has not crossed the scored start boundary")
    expected_run = controller.expected_by_run.get(reservation.run_id)
    if not isinstance(expected_run, Mapping):
        raise ProofPlaneError("reservation is absent from the controller expected runs")
    immutable = {
        field: controller.expected[field]
        for field in (
            "registrationSha256",
            "scheduleSha256",
            "expectedRunSetSha256",
            "preflightReceiptSha256",
            "qualificationReceiptSetSha256",
        )
    }
    immutable["expectedRunSha256"] = canonical_digest(dict(expected_run))
    try:
        bundle = validate_attempt_bundle(
            controller.private_root,
            reservation.run_id,
            expected_run=expected_run,
            immutable_start_bindings=immutable,
            reservation_entry_sha256=reservation.reservation_entry_sha256,
        )
    except ProofPlaneError as exc:
        raise AttemptRecoveryRequired(
            "consumed attempt lacks one complete independently valid terminal bundle"
        ) from exc
    return controller.record_terminal(
        reservation.run_id,
        bundle.paths.terminal_receipt,
    )


def run_model_attempt(
    *,
    controller: StudyRunController,
    reservation: ReservationHandle,
    registration_path: Path,
    expected_run_set_path: Path,
    preflight_receipt_path: Path,
    qualification_receipt_set_path: Path,
    task_artifact_set_summary_path: Path,
    repo_root: Path,
    artifact_root: Path,
    private_root: Path,
    runtime: Path,
    codex_path: Path,
    maximum_transcript_bytes: int = 20_000_000,
) -> dict[str, Any]:
    """Execute one and only one preregistered model attempt.

    This function never opens a holdout bundle and never grades.  Frozen-study
    admission failures occur before the controller-owned write-once start.  A
    caller cannot select a run ID: it must present the exact journal-backed
    :class:`ReservationHandle` returned by ``controller.reserve_next()``.

    After the start, a terminal is published only when independent VM-absence
    proof, patch capture, the closed model result, and the complete attempt
    bundle all validate.  Otherwise the scored start remains non-terminal and
    :class:`AttemptRecoveryRequired` is raised; a model retry is never made.
    """

    if (
        not isinstance(maximum_transcript_bytes, int)
        or isinstance(maximum_transcript_bytes, bool)
        or not 1024 <= maximum_transcript_bytes <= 20_000_000
    ):
        raise ProofPlaneError("maximum_transcript_bytes is outside the closed limit")
    if type(controller) is not StudyRunController:
        raise ProofPlaneError("controller must be one concrete StudyRunController")
    if not isinstance(reservation, ReservationHandle):
        raise ProofPlaneError("reservation must be returned by StudyRunController.reserve_next")
    if (
        not isinstance(private_root, Path)
        or not private_root.is_absolute()
        or controller.private_root != private_root.resolve()
    ):
        raise ProofPlaneError("controller private root differs from the attempt private root")
    if (
        not isinstance(expected_run_set_path, Path)
        or not expected_run_set_path.is_absolute()
        or controller.expected_run_set_path != expected_run_set_path.resolve()
    ):
        raise ProofPlaneError("controller expected-run set differs from the attempt input")
    run_id = reservation.run_id
    admission = _load_trusted_attempt_admission(
        run_id=run_id,
        registration_path=registration_path,
        expected_run_set_path=expected_run_set_path,
        preflight_receipt_path=preflight_receipt_path,
        qualification_receipt_set_path=qualification_receipt_set_path,
        task_artifact_set_summary_path=task_artifact_set_summary_path,
        repo_root=repo_root,
        artifact_root=artifact_root,
        private_root=private_root,
        runtime=runtime,
        codex_path=codex_path,
    )
    expected_run = admission["expectedRun"]
    normalized_task = admission["task"]
    limits = admission["limits"]
    registration = admission["registration"]
    registration_sha256 = admission["registrationSha256"]
    schedule_sha256 = admission["scheduleSha256"]
    expected_run_set_sha256 = admission["expectedRunSetSha256"]
    preflight_receipt_sha256 = admission["preflightReceiptSha256"]
    qualification_receipt_set_sha256 = admission["qualificationReceiptSetSha256"]
    qualification = admission["qualification"]
    runtime_tcb_document = validate_apple_container_tcb_document(
        admission["runtimeTcb"]
    )
    runtime_tcb_sha256 = _sha256(
        admission["runtimeTcbSha256"],
        "trusted admission runtimeTcbSha256",
    )
    if runtime_tcb_document["tcbSha256"] != runtime_tcb_sha256:
        raise ProofPlaneError(
            "trusted admission runtime TCB document and digest differ"
        )
    image_reference = normalized_task["environment"]["imageReference"]
    image_digest = normalized_task["environment"]["imageDigest"]
    qualified_image_store = validate_local_image_store_observation(
        qualification["imageAliasVerification"]["storeAfter"],
        image_reference=image_reference,
        image_digest=image_digest,
        field="qualified model image-store observation",
    )
    admitted_image_store = validate_local_image_store_observation(
        admission["imageStoreObservation"],
        image_reference=image_reference,
        image_digest=image_digest,
        field="trusted-admission live image-store observation",
    )
    if admitted_image_store != qualified_image_store:
        raise ProofPlaneError(
            "trusted-admission image store differs from qualification"
        )
    guest_execution_tcb_sha256 = _sha256(
        qualification["imageAliasVerification"]["guestExecutionTcbSha256"],
        "qualified guest execution TCB digest",
    )
    uid_gid = admission["uidGid"]
    source_archive = admission["sourceArchive"]
    prompt = admission["prompt"]
    broker_config = admission["brokerConfig"]
    artifacts = admission["artifactPaths"]
    ordinal = admission["ordinal"]
    if admission.get("runId") != run_id or ordinal != reservation.ordinal:
        raise ProofPlaneError("controller reservation differs from trusted attempt admission")
    repo_root = repo_root.resolve()
    private_root = private_root.resolve()
    runtime = runtime.resolve()
    codex_path = codex_path.resolve()

    container_name = attempt_container_name(run_id)
    read_only_mounts = []
    jstack_mcp = None
    if expected_run["mode"] == "operational" and expected_run["condition"] == "jstack":
        server = admission["server"]
        surface = admission["surface"]
        read_only_mounts.append(ReadOnlyMount(server, "/opt/jstack/jstack_mcp_server.py"))
        jstack_mcp = {
            "runtimeCommand": str(runtime),
            "containerId": container_name,
            "user": uid_gid,
            "serverPath": "/opt/jstack/jstack_mcp_server.py",
            "enabledTools": surface["names"],
            "toolTimeoutSeconds": min(int(limits["wallClockSeconds"]), 1900),
        }
    command = codex_command(
        codex_path=codex_path,
        empty_home=artifacts["codexHome"],
        broker_config=artifacts["brokerConfig"],
        repo_root=repo_root,
        model=registration["host"]["model"],
        reasoning_effort=FROZEN_REASONING_EFFORT,
        jstack_mcp=jstack_mcp,
    )
    model_instance_id = canonical_digest(
        {
            "schemaVersion": "jstack.eval.model-instance-plan.v1",
            "runId": run_id,
            "ordinal": ordinal,
            "reservationEntrySha256": reservation.reservation_entry_sha256,
            "containerName": container_name,
            "imageDigest": image_digest,
            "runtimeSha256": registration["executor"]["runtimeSha256"],
            "runtimeTcbSha256": runtime_tcb_sha256,
            "guestExecutionTcbSha256": guest_execution_tcb_sha256,
            "imageStoreObservationSha256": canonical_digest(
                qualified_image_store
            ),
        }
    )
    frozen_source_content_sha256 = _sha256(
        normalized_task["environment"]["toolVersions"].get(
            "source-content-sha256"
        ),
        "task source content digest",
    )
    trusted_attempt_plan = TrustedAttemptPlan(
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        broker_config_sha256=broker_config["configSha256"],
        command_sha256=canonical_digest(list(command)),
        model_instance_id_sha256=model_instance_id,
        source_archive_sha256=file_digest(source_archive),
        source_content_sha256=frozen_source_content_sha256,
        baseline_commit=normalized_task["baseline"]["commit"],
        baseline_result_sha256=_sha256(
            normalized_task["baseline"]["testResultSha256"],
            "task baseline result digest",
        ),
        runtime_tcb_sha256=runtime_tcb_sha256,
        image_store_observation_sha256=canonical_digest(
            qualified_image_store
        ),
    )

    # The controller owns the irreversible boundary.  Every value above is a
    # pure path/digest/argv derivation; trusted admission may create only the
    # shared ``attempts`` directory while confirming deterministic paths are
    # absent.  It does not create any run-specific file or workspace.  The
    # anchored reservation is revalidated under the controller lock immediately
    # before the start receipt is published.
    start_receipt = controller.begin_reserved_attempt(
        reservation,
        trusted_attempt_plan,
    )
    planned_start = _planned_attempt_evidence_paths(private_root, run_id)["start"]
    if start_receipt != planned_start or start_receipt.is_symlink() or not start_receipt.is_file():
        raise AttemptRecoveryRequired("controller did not publish the deterministic attempt start")
    start_value = load_json(start_receipt, maximum_bytes=200_000)
    if (
        start_value.get("runId") != run_id
        or start_value.get("ordinal") != ordinal
        or start_value.get("reservationEntrySha256")
        != reservation.reservation_entry_sha256
        or start_value.get("trustedAttemptPlan") != trusted_attempt_plan.as_dict()
        or start_value.get("trustedAttemptPlanSha256") != trusted_attempt_plan.sha256
    ):
        raise AttemptRecoveryRequired("controller start differs from the trusted attempt plan")
    started = time.monotonic()
    layout = None
    invocation = None
    transcript = b""
    stderr = b""
    parsed = {
        "terminalStatus": "failed",
        "reasonCode": "model-vm-operation-failed",
        "complete": False,
        "truncated": False,
        "returnCode": None,
        "tokenCount": 0,
        "usage": {"inputTokens": 0, "cachedInputTokens": 0, "outputTokens": 0},
        "finalMessage": None,
        "threadIdSha256": None,
        "terminalErrorSha256": None,
        "eventCount": 0,
    }
    container_started = False
    model_instance_destroyed = False
    diagnostic_sha256 = None
    interrupted: Optional[BaseException] = None
    workspace_prepared = False
    model_start_requested = False
    # Trusted admission just performed an exact full-document live inspection.
    # A container launch replaces this baseline with a second observation taken
    # immediately before ``managed_container``.
    runtime_tcb_before_sha256 = runtime_tcb_sha256
    runtime_tcb_after_sha256: Optional[str] = None
    runtime_tcb_post_inspection_attempted = False
    runtime_tcb_integrity_error: Optional[BaseException] = None
    image_store_before: Optional[dict[str, Any]] = admitted_image_store
    image_store_after: Optional[dict[str, Any]] = None
    image_store_integrity_error: Optional[BaseException] = None
    container_invocation_sha256: Optional[str] = None
    try:
        _prepare_attempt_directories(artifacts)
        _retain_private_bytes_once_or_equal(
            artifacts["prompt"],
            prompt,
            field="model prompt",
            maximum_bytes=1_000_000,
        )
        broker_payload = (
            json.dumps(broker_config, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n"
        ).encode("utf-8")
        _retain_private_bytes_once_or_equal(
            artifacts["brokerConfig"],
            broker_payload,
            field="proof broker configuration",
            maximum_bytes=1_000_000,
        )
        layout = prepare_source_workspace(
            source_archive,
            expected_archive_sha256=normalized_task["source"]["sourceArchiveSha256"],
            expected_content_sha256=_sha256(
                normalized_task["environment"]["toolVersions"].get(
                    "source-content-sha256"
                ),
                "task source content digest",
            ),
            attempt_root=artifacts["sourceRoot"],
        )
        workspace_prepared = True
        runtime_tcb_before = _inspect_exact_runtime_tcb(
            runtime,
            runtime_tcb_document,
            "immediate pre-model runtime TCB",
        )
        runtime_tcb_before_sha256 = runtime_tcb_before.tcb_sha256
        image_store_before = inspect_local_image_store(
            runtime,
            runtime_tcb_before.document,
            image_reference,
            image_digest,
        )
        if image_store_before != qualified_image_store:
            raise ProofPlaneError(
                "immediate pre-model image store differs from qualification"
            )
        invocation = build_model_vm_argv(
            runtime=runtime,
            container_name=container_name,
            image_reference=normalized_task["environment"]["imageReference"],
            workspace=layout.workspace,
            git_metadata=layout.git_metadata,
            kernel_path=Path(runtime_tcb_before.kernel_path),
            kernel_sha256=runtime_tcb_before.kernel_sha256,
            init_image_reference=(
                runtime_tcb_before.immutable_init_image_reference
            ),
            init_image_index_sha256=runtime_tcb_document["initImage"][
                "indexDigest"
            ],
            uid_gid=uid_gid,
            lifetime_seconds=min(int(limits["wallClockSeconds"]) + 120, 3600),
            read_only_mounts=tuple(read_only_mounts),
        )
        container_invocation_sha256 = canonical_digest(list(invocation.argv))
        if (
            not invocation.qualification_required
            or qualification["image"]["digest"]
            != normalized_task["environment"]["imageDigest"]
        ):
            raise ProofPlaneError(
                "model invocation did not retain its qualification boundary"
            )
        model_start_requested = True
        try:
            try:
                with managed_container(
                    invocation,
                    startup_timeout=min(int(limits["wallClockSeconds"]), 120),
                ) as container_start:
                    container_started = True
                    del container_start  # Startup bytes are diagnostics, never model identity.
                    try:
                        remaining_seconds = min(
                            3600,
                            int(int(limits["wallClockSeconds"]) - (time.monotonic() - started)),
                        )
                        if remaining_seconds < 1:
                            parsed["terminalStatus"] = "timed-out"
                            parsed["reasonCode"] = "wall-clock-timeout-before-model-start"
                        else:
                            completed = _run(
                                command,
                                cwd=repo_root,
                                stdin=prompt,
                                timeout=remaining_seconds,
                                maximum_output=maximum_transcript_bytes,
                            )
                            transcript = completed.stdout
                            stderr = completed.stderr
                            try:
                                parsed = parse_codex_jsonl(
                                    transcript,
                                    returncode=completed.returncode,
                                    token_limit=int(limits["tokenLimit"]),
                                )
                            except ProofPlaneError as exc:
                                parsed["reasonCode"] = "invalid-codex-jsonl"
                                diagnostic_sha256 = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
                    except BoundedProcessError as exc:
                        transcript = exc.stdout
                        stderr = exc.stderr
                        parsed["terminalStatus"] = "timed-out" if exc.kind == "timed-out" else "failed"
                        parsed["reasonCode"] = (
                            "wall-clock-timeout"
                            if exc.kind == "timed-out"
                            else "bounded-capture-failure"
                        )
                        parsed["truncated"] = exc.kind == "output-limit"
                        diagnostic_sha256 = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
                    except Exception as exc:
                        parsed["reasonCode"] = "host-codex-operation-failed"
                        diagnostic_sha256 = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
            finally:
                runtime_tcb_post_inspection_attempted = True
                try:
                    runtime_tcb_after = _inspect_exact_runtime_tcb(
                        runtime,
                        runtime_tcb_document,
                        "immediate post-model runtime TCB",
                    )
                    runtime_tcb_after_sha256 = runtime_tcb_after.tcb_sha256
                except (Exception, KeyboardInterrupt, SystemExit) as exc:
                    runtime_tcb_integrity_error = exc
                    raise
                try:
                    image_store_after = inspect_local_image_store(
                        runtime,
                        runtime_tcb_after.document,
                        image_reference,
                        image_digest,
                    )
                    if image_store_after != image_store_before:
                        raise ProofPlaneError(
                            "target image store drifted across model execution"
                        )
                except (Exception, KeyboardInterrupt, SystemExit) as exc:
                    image_store_integrity_error = exc
                    raise
        except (Exception, KeyboardInterrupt, SystemExit) as exc:
            parsed["terminalStatus"] = "failed"
            parsed["reasonCode"] = (
                "model-vm-operation-failed"
                if model_start_requested
                else "runner-preparation-failed"
            )
            parsed["complete"] = False
            diagnostic_sha256 = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                interrupted = exc
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        # Failures while materializing the source tree, creating the broker
        # artifacts, or constructing the qualified invocation happen after the
        # write-once start and must therefore remain in the study denominator.
        parsed["terminalStatus"] = "failed"
        parsed["reasonCode"] = "runner-preparation-failed"
        parsed["complete"] = False
        diagnostic_sha256 = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            interrupted = exc
    finally:
        if not runtime_tcb_post_inspection_attempted:
            runtime_tcb_post_inspection_attempted = True
            try:
                runtime_tcb_after = _inspect_exact_runtime_tcb(
                    runtime,
                    runtime_tcb_document,
                    "post-preparation runtime TCB",
                )
                runtime_tcb_after_sha256 = runtime_tcb_after.tcb_sha256
            except (Exception, KeyboardInterrupt, SystemExit) as exc:
                runtime_tcb_integrity_error = exc
                diagnostic_sha256 = canonical_digest(
                    {
                        "priorDiagnosticSha256": diagnostic_sha256,
                        "runtimeTcbInspectionErrorSha256": hashlib.sha256(
                            str(exc).encode("utf-8")
                        ).hexdigest(),
                    }
                )
                if isinstance(exc, (KeyboardInterrupt, SystemExit)) and interrupted is None:
                    interrupted = exc
            if runtime_tcb_after_sha256 is not None:
                try:
                    image_store_after = inspect_local_image_store(
                        runtime,
                        runtime_tcb_after.document,
                        image_reference,
                        image_digest,
                    )
                    if image_store_after != qualified_image_store:
                        raise ProofPlaneError(
                            "post-preparation image store differs from qualification"
                        )
                except (Exception, KeyboardInterrupt, SystemExit) as exc:
                    image_store_integrity_error = exc
                    diagnostic_sha256 = canonical_digest(
                        {
                            "priorDiagnosticSha256": diagnostic_sha256,
                            "imageStoreInspectionErrorSha256": hashlib.sha256(
                                str(exc).encode("utf-8")
                            ).hexdigest(),
                        }
                    )
                    if isinstance(exc, (KeyboardInterrupt, SystemExit)) and interrupted is None:
                        interrupted = exc
        try:
            model_instance_destroyed = _container_absence_proven(runtime, container_name)
        except (Exception, KeyboardInterrupt, SystemExit) as exc:
            model_instance_destroyed = False
            diagnostic_sha256 = canonical_digest(
                {
                    "priorDiagnosticSha256": diagnostic_sha256,
                    "absenceProbeErrorSha256": hashlib.sha256(
                        str(exc).encode("utf-8")
                    ).hexdigest(),
                }
            )
            if isinstance(exc, (KeyboardInterrupt, SystemExit)) and interrupted is None:
                interrupted = exc
        patch_capture_succeeded = False
        patch_bytes = b""
        workspace_content_sha256 = frozen_source_content_sha256
        if model_instance_destroyed:
            if workspace_prepared and layout is not None:
                try:
                    patch_artifact = capture_patch(layout)
                    patch_bytes = patch_artifact.patch
                    workspace_content_sha256 = patch_artifact.workspace_content_sha256
                    patch_capture_succeeded = True
                except ProofPlaneError as exc:
                    parsed["terminalStatus"] = "failed"
                    parsed["complete"] = False
                    parsed["reasonCode"] = "patch-capture-failed"
                    diagnostic_sha256 = hashlib.sha256(
                        str(exc).encode("utf-8")
                    ).hexdigest()
            elif not model_start_requested:
                # Source preparation can fail before a model VM is requested.
                # An independent absence probe then proves there was no model
                # mutation; the only honest patch is empty and its workspace
                # content remains the frozen source digest.
                patch_capture_succeeded = True
                patch_bytes = b""
                workspace_content_sha256 = frozen_source_content_sha256
        else:
            parsed["terminalStatus"] = "blocked"
            parsed["complete"] = False
            parsed["reasonCode"] = "model-vm-destruction-unproven"

        try:
            # Retain all raw evidence that is safe even when recovery is needed.
            _prepare_attempt_directories(artifacts)
            _retain_private_bytes_once_or_equal(
                artifacts["prompt"],
                prompt,
                field="model prompt",
                maximum_bytes=1_000_000,
            )
            broker_payload = (
                json.dumps(
                    broker_config,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            _retain_private_bytes_once_or_equal(
                artifacts["brokerConfig"],
                broker_payload,
                field="proof broker configuration",
                maximum_bytes=1_000_000,
            )
            _retain_private_bytes_once_or_equal(
                artifacts["transcript"],
                transcript,
                field="Codex transcript",
                maximum_bytes=maximum_transcript_bytes,
            )
            _retain_private_bytes_once_or_equal(
                artifacts["stderr"],
                stderr,
                field="Codex stderr",
                maximum_bytes=maximum_transcript_bytes,
            )
        except (Exception, KeyboardInterrupt, SystemExit) as exc:
            raise AttemptRecoveryRequired(
                "started attempt evidence could not be retained atomically"
            ) from exc

        if not model_instance_destroyed or not patch_capture_succeeded:
            reason = (
                "model instance absence is unproven"
                if not model_instance_destroyed
                else "candidate patch capture is unproven"
            )
            raise AttemptRecoveryRequired(
                "%s; the scored cell remains started and must not be retried" % reason
            )
        if (
            runtime_tcb_integrity_error is not None
            or runtime_tcb_before_sha256 != runtime_tcb_sha256
            or runtime_tcb_after_sha256 != runtime_tcb_sha256
        ):
            raise AttemptRecoveryRequired(
                "runtime TCB integrity is unproven; the scored cell remains started "
                "and must not be retried"
            ) from runtime_tcb_integrity_error
        if (
            image_store_integrity_error is not None
            or image_store_before is None
            or image_store_after is None
            or image_store_before != qualified_image_store
            or image_store_after != qualified_image_store
        ):
            raise AttemptRecoveryRequired(
                "target image-store integrity is unproven; the scored cell remains "
                "started and must not be retried"
            ) from image_store_integrity_error
        if invocation is None or container_invocation_sha256 is None:
            raise AttemptRecoveryRequired(
                "model container invocation is unproven; the scored cell remains "
                "started and must not be retried"
            )

        try:
            _retain_private_bytes_once_or_equal(
                artifacts["patch"],
                patch_bytes,
                field="candidate patch",
                maximum_bytes=5_000_000,
            )
        except (Exception, KeyboardInterrupt, SystemExit) as exc:
            raise AttemptRecoveryRequired(
                "verified candidate patch could not be retained atomically"
            ) from exc
        elapsed_seconds = round(time.monotonic() - started, 3)
        if elapsed_seconds > int(limits["wallClockSeconds"]) and parsed["terminalStatus"] == "completed":
            parsed["terminalStatus"] = "timed-out"
            parsed["complete"] = False
            parsed["reasonCode"] = "wall-clock-budget-exceeded-after-teardown"
        finished_at = utc_now()
        model_result = {
            "schemaVersion": MODEL_RESULT_SCHEMA,
            "runId": run_id,
            "status": parsed["terminalStatus"],
            "reasonCode": parsed["reasonCode"],
            "startedAt": start_value["startedAt"],
            "finishedAt": finished_at,
            "wallClockSeconds": elapsed_seconds,
            "complete": parsed["complete"],
            "truncated": parsed["truncated"],
            "returnCode": parsed["returnCode"],
            "tokenCount": parsed["tokenCount"],
            "usage": parsed["usage"],
            "eventCount": parsed["eventCount"],
            "threadIdSha256": parsed["threadIdSha256"],
            "terminalErrorSha256": parsed["terminalErrorSha256"],
            "diagnosticSha256": diagnostic_sha256,
            "finalMessage": parsed["finalMessage"],
            "promptSha256": file_digest(artifacts["prompt"]),
            "commandSha256": canonical_digest(command),
            "brokerConfigSha256": broker_config["configSha256"],
            "modelInstanceIdSha256": model_instance_id,
            "containerStarted": container_started,
            "modelInstanceDestroyed": model_instance_destroyed,
            "sourceArchiveSha256": normalized_task["source"]["sourceArchiveSha256"],
            "sourceContentSha256": frozen_source_content_sha256,
            # ``prepare_source_workspace`` creates a deterministic local Git
            # commit for patch transport.  The upstream baseline identity is
            # independently frozen by the validated task and expected run.
            "baselineCommit": normalized_task["baseline"]["commit"],
            "workspaceContentSha256": workspace_content_sha256,
            "patchCaptureSucceeded": patch_capture_succeeded,
            "transcriptSha256": file_digest(artifacts["transcript"]),
            "stderrSha256": file_digest(artifacts["stderr"]),
            "patchSha256": file_digest(artifacts["patch"]),
            "runtimeTcbObservation": {
                "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
                "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
                "expectedSha256": runtime_tcb_sha256,
                "beforeSha256": runtime_tcb_before_sha256,
                "afterSha256": runtime_tcb_after_sha256,
            },
            "imageStoreObservation": {
                "expectedSha256": canonical_digest(qualified_image_store),
                "beforeSha256": canonical_digest(image_store_before),
                "afterSha256": canonical_digest(image_store_after),
            },
            "containerInvocationSha256": container_invocation_sha256,
        }
        try:
            validate_model_result(model_result)
            model_result_bytes = (
                json.dumps(
                    model_result,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            _retain_private_bytes_once_or_equal(
                artifacts["modelResult"],
                model_result_bytes,
                field="model result",
                maximum_bytes=20_000_000,
            )
            _prevalidate_attempt_artifacts(
                artifacts=artifacts,
                prompt=prompt,
                broker_config=broker_config,
                model_result=model_result,
                trusted_attempt_plan=trusted_attempt_plan,
            )
            terminal_receipt = terminalize_attempt(
                run_id=run_id,
                private_root=private_root,
                terminal={
                    "status": parsed["terminalStatus"],
                    "modelInstanceIdSha256": model_instance_id,
                    "modelResultSha256": file_digest(artifacts["modelResult"]),
                    "transcriptSha256": file_digest(artifacts["transcript"]),
                    "patchSha256": file_digest(artifacts["patch"]),
                },
            )
            immutable_start_bindings = {
                "registrationSha256": registration_sha256,
                "scheduleSha256": schedule_sha256,
                "expectedRunSetSha256": expected_run_set_sha256,
                "preflightReceiptSha256": preflight_receipt_sha256,
                "qualificationReceiptSetSha256": qualification_receipt_set_sha256,
                "expectedRunSha256": canonical_digest(dict(expected_run)),
            }
            validate_attempt_bundle(
                private_root,
                run_id,
                expected_run=expected_run,
                immutable_start_bindings=immutable_start_bindings,
                reservation_entry_sha256=reservation.reservation_entry_sha256,
                expected_trusted_attempt_plan=trusted_attempt_plan.as_dict(),
                expected_broker_config_sha256=broker_config["configSha256"],
                expected_study_id=registration["studyId"],
            )
            controller.record_terminal(run_id, terminal_receipt)
        except (Exception, KeyboardInterrupt, SystemExit) as exc:
            raise AttemptRecoveryRequired(
                "complete attempt evidence could not be validated and recorded"
            ) from exc

    report = {
        "schemaVersion": MODEL_ATTEMPT_REPORT_SCHEMA,
        "runId": run_id,
        "status": parsed["terminalStatus"],
        "modelInstanceDestroyed": model_instance_destroyed,
        "startReceipt": str(start_receipt),
        "terminalReceipt": str(terminal_receipt),
        "modelResult": str(artifacts["modelResult"]),
        "transcript": str(artifacts["transcript"]),
        "stderr": str(artifacts["stderr"]),
        "patch": str(artifacts["patch"]),
        "brokerConfig": str(artifacts["brokerConfig"]),
        "workspace": str(
            layout.workspace
            if layout is not None
            else artifacts["sourceRoot"] / "workspace"
        ),
        "modelResultSha256": file_digest(artifacts["modelResult"]),
        "transcriptSha256": file_digest(artifacts["transcript"]),
        "patchSha256": file_digest(artifacts["patch"]),
    }
    if interrupted is not None:
        raise interrupted
    return report


__all__ = [
    "AttemptRecoveryRequired",
    "BoundedProcessError",
    "MODEL_ATTEMPT_REPORT_SCHEMA",
    "MODEL_RESULT_SCHEMA",
    "PROOF_TOOLS",
    "RUNNER_VERSION",
    "attempt_container_name",
    "attempt_evidence_paths",
    "build_attempt_broker_config",
    "codex_cli_registration_binding",
    "codex_cli_provenance",
    "codex_command",
    "compose_model_prompt",
    "isolation_canary_script",
    "model_attempt_artifact_paths",
    "parse_codex_jsonl",
    "planned_attempt_evidence_paths",
    "preflight",
    "probe_mcp_tool_surface",
    "validate_frozen_study_admission",
    "reconcile_consumed_attempt",
    "run_model_attempt",
    "terminalize_attempt",
    "verify_registration_ref",
]
