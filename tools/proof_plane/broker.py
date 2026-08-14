#!/usr/bin/env python3
"""Secretless MCP bridge from a host Codex process into one isolated run VM."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional

from .common import (
    ProofPlaneError,
    append_ledger_event,
    canonical_digest,
    exact_fields,
    load_json,
    validate_ledger,
)


BROKER_CONFIG_SCHEMA = "jstack.proof-broker.config.v1"
BROKER_VERSION = "0.10.0-beta.1"
CONTAINER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
ENV_NAME_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MCP_FRAME_BYTE_LIMIT = 1_000_000
TOOL_NAMES = frozenset(("proof_exec", "proof_read_file", "proof_apply_patch", "proof_git_evidence"))
BROKER_BINDING_FIELDS = ("studyId", "runId", "registrationSha256", "configSha256")
BROKER_CONFIG_FIELDS = (
    "schemaVersion",
    "studyId",
    "runId",
    "registrationSha256",
    "configSha256",
    "runtimeCommand",
    "isolationCommand",
    "containerId",
    "workspaceRoot",
    "user",
    "toolCallLimit",
    "commandTimeoutSeconds",
    "outputByteLimit",
    "ledgerPath",
)


def proof_tool_descriptors() -> list[dict[str, Any]]:
    """Return the frozen, config-independent four-tool MCP surface."""

    return [
        {
            "name": "proof_exec",
            "description": "Run one argv command inside the isolated, offline benchmark VM workspace.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["args"],
                "properties": {
                    "args": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"type": "string"}},
                    "cwd": {"type": "string", "default": "."},
                    "environment": {"type": "object", "additionalProperties": {"type": "string"}},
                    "timeoutSeconds": {"type": "integer", "minimum": 1},
                },
            },
        },
        {
            "name": "proof_read_file",
            "description": "Read a bounded line range from one workspace file inside the benchmark VM.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"},
                    "startLine": {"type": "integer", "minimum": 1, "default": 1},
                    "endLine": {"type": "integer", "minimum": 1, "default": 400},
                },
            },
        },
        {
            "name": "proof_apply_patch",
            "description": "Check and apply a unified Git patch inside the benchmark VM workspace.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["patch"],
                "properties": {"patch": {"type": "string", "minLength": 1, "maxLength": 200000}},
            },
        },
        {
            "name": "proof_git_evidence",
            "description": "Return bounded status, diff statistics, and patch text from the isolated workspace.",
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
        },
    ]


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ProofPlaneError("%s must be a closed identifier" % field)
    return value


def _closed_json(value: Any, field: str) -> None:
    """Reject values that cannot participate in deterministic evidence."""

    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProofPlaneError("%s contains a non-finite number" % field)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _closed_json(item, "%s[%d]" % (field, index))
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProofPlaneError("%s object keys must be strings" % field)
            _closed_json(item, "%s.%s" % (field, key))
        return
    raise ProofPlaneError("%s contains a non-JSON value" % field)


def broker_config_digest(value: Mapping[str, Any]) -> str:
    """Return the self-excluding digest used to bind a broker configuration."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("broker config must be an object")
    payload = dict(value)
    payload.pop("configSha256", None)
    _closed_json(payload, "broker config")
    return canonical_digest(payload)


def _reject_symlink_components(path: Path, field: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ProofPlaneError("%s must not resolve through a symlink" % field)


def _guest_relative_path(value: Any, field: str, *, allow_root: bool = True) -> str:
    if not isinstance(value, str) or len(value) > 1000 or "\\" in value or "\x00" in value:
        raise ProofPlaneError("%s must be a normalized guest-relative path" % field)
    if not value and allow_root:
        return "."
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ProofPlaneError("%s must be a normalized guest-relative path" % field)
    return path.as_posix()


def validate_broker_config(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("broker config must be an object")
    exact_fields(
        value,
        BROKER_CONFIG_FIELDS,
        "broker config",
    )
    _closed_json(value, "broker config")
    if value["schemaVersion"] != BROKER_CONFIG_SCHEMA:
        raise ProofPlaneError("unsupported broker config schemaVersion")
    _identifier(value["studyId"], "studyId")
    _identifier(value["runId"], "runId")
    _sha256(value["registrationSha256"], "registrationSha256")
    _sha256(value["configSha256"], "configSha256")
    if value["configSha256"] != broker_config_digest(value):
        raise ProofPlaneError("configSha256 does not bind the exact broker configuration")
    runtime = Path(value["runtimeCommand"])
    if not runtime.is_absolute() or runtime.is_symlink() or not runtime.is_file() or not os.access(runtime, os.X_OK):
        raise ProofPlaneError("runtimeCommand must be an absolute executable, regular, non-symlink file")
    isolation = value["isolationCommand"]
    if isolation != "/usr/bin/bwrap":
        raise ProofPlaneError("isolationCommand must be the task image's /usr/bin/bwrap")
    if not isinstance(value["containerId"], str) or not CONTAINER_ID_PATTERN.fullmatch(value["containerId"]):
        raise ProofPlaneError("containerId is invalid")
    root = value["workspaceRoot"]
    if not isinstance(root, str) or PurePosixPath(root).as_posix() != root or root != "/workspace":
        raise ProofPlaneError("workspaceRoot must be exactly /workspace")
    if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", str(value["user"])):
        raise ProofPlaneError("broker user must be a numeric uid:gid")
    uid, gid = (int(item) for item in value["user"].split(":"))
    if uid == 0 or gid == 0:
        raise ProofPlaneError("broker user must not be root")
    for field, minimum, maximum in (
        ("toolCallLimit", 1, 10_000),
        ("commandTimeoutSeconds", 1, 3_600),
        ("outputByteLimit", 1_024, 1_000_000),
    ):
        item = value[field]
        if not isinstance(item, int) or isinstance(item, bool) or not minimum <= item <= maximum:
            raise ProofPlaneError("%s must be an integer between %d and %d" % (field, minimum, maximum))
    ledger = Path(value["ledgerPath"])
    if not ledger.is_absolute() or ledger.is_symlink():
        raise ProofPlaneError("ledgerPath must be an absolute non-symlink path")
    _reject_symlink_components(ledger.parent, "ledgerPath")
    if ledger.exists() and not ledger.is_file():
        raise ProofPlaneError("ledgerPath must identify a regular file")
    return dict(value)


class RuntimeClient:
    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = validate_broker_config(config)

    def _workspace(self, relative: str) -> str:
        root = PurePosixPath(self.config["workspaceRoot"])
        if relative == ".":
            return root.as_posix()
        return (root / relative).as_posix()

    def execute(
        self,
        args: list[str],
        *,
        cwd: str = ".",
        environment: Optional[Mapping[str, str]] = None,
        stdin_text: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        tool_name: Optional[str] = None,
        tool_call_ordinal: Optional[int] = None,
        command_ordinal: Optional[int] = None,
        arguments_sha256: Optional[str] = None,
    ) -> dict[str, Any]:
        if not isinstance(args, list) or not args or len(args) > 64:
            raise ProofPlaneError("args must contain 1 to 64 argv strings")
        normalized_args = []
        for index, item in enumerate(args):
            if not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096:
                raise ProofPlaneError("args[%d] is invalid" % index)
            normalized_args.append(item)
        if sum(len(item) for item in normalized_args) > 32_768:
            raise ProofPlaneError("command argv exceeds the 32 KiB limit")
        relative_cwd = _guest_relative_path(cwd, "cwd")
        environment_args: list[str] = []
        if environment is not None and not isinstance(environment, Mapping):
            raise ProofPlaneError("command environment must be an object")
        if len(environment or {}) > 64:
            raise ProofPlaneError("command environment exceeds 64 entries")
        normalized_environment: dict[str, str] = {}
        for name, item in sorted((environment or {}).items(), key=lambda pair: str(pair[0])):
            if (
                not isinstance(name, str)
                or not ENV_NAME_PATTERN.fullmatch(name)
                or not isinstance(item, str)
                or "\x00" in item
                or len(item) > 4096
            ):
                raise ProofPlaneError("command environment is invalid")
            normalized_environment[name] = item
            environment_args.extend(["--setenv", name, item])
        timeout = self.config["commandTimeoutSeconds"] if timeout_seconds is None else timeout_seconds
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= self.config["commandTimeoutSeconds"]:
            raise ProofPlaneError("timeoutSeconds exceeds the broker limit")
        if tool_name not in TOOL_NAMES:
            raise ProofPlaneError("broker command toolName is invalid")
        for field, item in (("toolCallOrdinal", tool_call_ordinal), ("commandOrdinal", command_ordinal)):
            if not isinstance(item, int) or isinstance(item, bool) or item < 1:
                raise ProofPlaneError("%s must be a positive integer" % field)
        _sha256(arguments_sha256, "argumentsSha256")
        environment_sha256 = canonical_digest(normalized_environment)
        inner = [
            self.config["isolationCommand"],
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
            self.config["workspaceRoot"],
            self.config["workspaceRoot"],
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
            "GIT_DIR",
            "/proof-git",
            "--setenv",
            "GIT_WORK_TREE",
            self.config["workspaceRoot"],
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            *environment_args,
            "--chdir",
            self._workspace(relative_cwd),
            "--",
            "/usr/bin/timeout",
            "--signal=KILL",
            str(timeout),
            *normalized_args,
        ]
        command = [
            self.config["runtimeCommand"],
            "exec",
            "--user",
            self.config["user"],
            "--workdir",
            self.config["workspaceRoot"],
            self.config["containerId"],
            *inner,
        ]
        if stdin_text is not None:
            if not isinstance(stdin_text, str) or len(stdin_text.encode("utf-8")) > 250_000:
                raise ProofPlaneError("command stdin exceeds the 250000-byte limit")
        safe_host_env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        if os.environ.get("TMPDIR"):
            safe_host_env["TMPDIR"] = os.environ["TMPDIR"]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=safe_host_env,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProofPlaneError("broker command could not start") from exc
        if stdin_text is not None and process.stdin is not None:
            try:
                process.stdin.write(stdin_text.encode("utf-8"))
            except BrokenPipeError:
                pass
            finally:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
        stdout, stderr, stdout_digest, stderr_digest, truncated, timed_out = self._drain(
            process,
            timeout + 10,
        )
        if process.returncode is None:
            raise ProofPlaneError("broker command did not reach a terminal process state")
        result = {
            "returncode": 124 if timed_out else int(process.returncode),
            "stdout": stdout,
            "stderr": stderr,
            "timedOut": timed_out or process.returncode == 124,
            "truncated": truncated,
        }
        result_sha256 = canonical_digest(result)
        exit_sha256 = canonical_digest({"exitCode": result["returncode"], "timedOut": result["timedOut"]})
        append_ledger_event(
            Path(self.config["ledgerPath"]),
            {
                "type": "broker-command",
                **{field: self.config[field] for field in BROKER_BINDING_FIELDS},
                "toolName": tool_name,
                "toolCallOrdinal": tool_call_ordinal,
                "commandOrdinal": command_ordinal,
                "argumentsSha256": arguments_sha256,
                "environmentSha256": environment_sha256,
                "effectiveTimeoutSeconds": timeout,
                "argvSha256": canonical_digest(normalized_args),
                "cwd": relative_cwd,
                "stdinSha256": hashlib.sha256((stdin_text or "").encode()).hexdigest(),
                "exitCode": result["returncode"],
                "exitSha256": exit_sha256,
                "timedOut": result["timedOut"],
                "truncated": result["truncated"],
                "stdoutSha256": stdout_digest,
                "stderrSha256": stderr_digest,
                "resultSha256": result_sha256,
            },
        )
        return result

    @staticmethod
    def _terminate_and_wait(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                try:
                    process.kill()
                except (OSError, ProcessLookupError):
                    pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ProofPlaneError("broker command could not be reaped after termination") from exc
        except OSError as exc:
            raise ProofPlaneError("broker command wait failed") from exc

    def _drain(
        self,
        process: subprocess.Popen[bytes],
        timeout_seconds: int,
    ) -> tuple[str, str, str, str, bool, bool]:
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
        limit = self.config["outputByteLimit"]
        truncated = False
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if timed_out:
                        break
                    timed_out = True
                    self._terminate_and_wait(process)
                    deadline = time.monotonic() + 1.0
                    remaining = 1.0
                events = selector.select(min(max(remaining, 0.0), 1.0))
                if timed_out and not events and time.monotonic() >= deadline:
                    break
                for key, _mask in events:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65_536)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    stream = key.data
                    digests[stream].update(chunk)
                    available = max(0, limit - len(captured[stream]))
                    captured[stream].extend(chunk[:available])
                    if len(chunk) > available:
                        truncated = True
            if process.poll() is None:
                remaining = max(0.0, deadline - time.monotonic())
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._terminate_and_wait(process)
                except OSError as exc:
                    raise ProofPlaneError("broker command wait failed") from exc
            else:
                try:
                    process.wait(timeout=0)
                except OSError as exc:
                    raise ProofPlaneError("broker command wait failed") from exc
        finally:
            selector.close()
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
        return (
            bytes(captured["stdout"]).decode("utf-8", errors="replace"),
            bytes(captured["stderr"]).decode("utf-8", errors="replace"),
            digests["stdout"].hexdigest(),
            digests["stderr"].hexdigest(),
            truncated,
            timed_out,
        )


class ProofBroker:
    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = validate_broker_config(config)
        self.runtime = RuntimeClient(self.config)
        self.tool_calls = self._restore_tool_calls()

    def _binding(self) -> dict[str, str]:
        return {field: self.config[field] for field in BROKER_BINDING_FIELDS}

    def _restore_tool_calls(self) -> int:
        ledger = Path(self.config["ledgerPath"])
        if not ledger.exists():
            return 0
        entries = validate_ledger(ledger)
        starts: dict[int, dict[str, Any]] = {}
        commands: dict[int, list[dict[str, Any]]] = {}
        results: set[int] = set()
        expected_binding = self._binding()
        for entry in entries:
            event = entry["event"]
            if not isinstance(event, Mapping):
                raise ProofPlaneError("broker ledger event must be an object")
            event_type = event.get("type")
            if not isinstance(event_type, str) or not event_type.startswith("broker-"):
                continue
            for field, expected in expected_binding.items():
                if event.get(field) != expected:
                    raise ProofPlaneError("broker ledger %s binding mismatch" % field)
            if event_type == "broker-tool-start":
                exact_fields(
                    event,
                    (
                        "type",
                        *BROKER_BINDING_FIELDS,
                        "toolName",
                        "toolCallOrdinal",
                        "argumentsSha256",
                        "environmentSha256",
                        "effectiveTimeoutSeconds",
                    ),
                    "broker tool-start event",
                )
                ordinal = event["toolCallOrdinal"]
                if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal != len(starts) + 1:
                    raise ProofPlaneError("broker ledger tool-call ordinals are discontinuous")
                if event["toolName"] not in TOOL_NAMES:
                    raise ProofPlaneError("broker ledger toolName is invalid")
                _sha256(event["argumentsSha256"], "ledger argumentsSha256")
                _sha256(event["environmentSha256"], "ledger environmentSha256")
                timeout = event["effectiveTimeoutSeconds"]
                if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= self.config["commandTimeoutSeconds"]:
                    raise ProofPlaneError("broker ledger timeout is invalid")
                starts[ordinal] = dict(event)
                commands[ordinal] = []
            elif event_type == "broker-command":
                exact_fields(
                    event,
                    (
                        "type",
                        *BROKER_BINDING_FIELDS,
                        "toolName",
                        "toolCallOrdinal",
                        "commandOrdinal",
                        "argumentsSha256",
                        "environmentSha256",
                        "effectiveTimeoutSeconds",
                        "argvSha256",
                        "cwd",
                        "stdinSha256",
                        "exitCode",
                        "exitSha256",
                        "timedOut",
                        "truncated",
                        "stdoutSha256",
                        "stderrSha256",
                        "resultSha256",
                    ),
                    "broker command event",
                )
                ordinal = event["toolCallOrdinal"]
                if ordinal not in starts or ordinal in results:
                    raise ProofPlaneError("broker command does not belong to an open tool call")
                start = starts[ordinal]
                for field in ("toolName", "argumentsSha256", "environmentSha256", "effectiveTimeoutSeconds"):
                    if event[field] != start[field]:
                        raise ProofPlaneError("broker command evidence does not match its tool reservation")
                command_ordinal = event["commandOrdinal"]
                if (
                    not isinstance(command_ordinal, int)
                    or isinstance(command_ordinal, bool)
                    or command_ordinal != len(commands[ordinal]) + 1
                ):
                    raise ProofPlaneError("broker command ordinals are discontinuous")
                for field in (
                    "argvSha256",
                    "stdinSha256",
                    "stdoutSha256",
                    "stderrSha256",
                    "resultSha256",
                    "exitSha256",
                ):
                    _sha256(event[field], "ledger %s" % field)
                if not isinstance(event["exitCode"], int) or isinstance(event["exitCode"], bool):
                    raise ProofPlaneError("broker ledger exitCode is invalid")
                if not isinstance(event["timedOut"], bool) or not isinstance(event["truncated"], bool):
                    raise ProofPlaneError("broker ledger terminal flags are invalid")
                if event["exitSha256"] != canonical_digest(
                    {"exitCode": event["exitCode"], "timedOut": event["timedOut"]}
                ):
                    raise ProofPlaneError("broker ledger exit digest is inconsistent")
                commands[ordinal].append(dict(event))
            elif event_type == "broker-tool-result":
                exact_fields(
                    event,
                    (
                        "type",
                        *BROKER_BINDING_FIELDS,
                        "toolName",
                        "toolCallOrdinal",
                        "status",
                        "resultSha256",
                        "commandCount",
                        "commandEvidenceSha256",
                    ),
                    "broker tool-result event",
                )
                ordinal = event["toolCallOrdinal"]
                if ordinal not in starts or ordinal in results:
                    raise ProofPlaneError("broker tool result is duplicate or unreserved")
                if event["toolName"] != starts[ordinal]["toolName"]:
                    raise ProofPlaneError("broker tool result name does not match its reservation")
                if event["status"] not in ("succeeded", "failed"):
                    raise ProofPlaneError("broker tool result status is invalid")
                _sha256(event["resultSha256"], "ledger resultSha256")
                _sha256(event["commandEvidenceSha256"], "ledger commandEvidenceSha256")
                if (
                    not isinstance(event["commandCount"], int)
                    or isinstance(event["commandCount"], bool)
                    or event["commandCount"] != len(commands[ordinal])
                ):
                    raise ProofPlaneError("broker tool result commandCount is inconsistent")
                if event["commandEvidenceSha256"] != self._command_evidence_digest(commands[ordinal]):
                    raise ProofPlaneError("broker tool result command evidence digest is inconsistent")
                results.add(ordinal)
            else:
                raise ProofPlaneError("unsupported broker ledger event type %r" % event_type)
        return len(starts)

    @staticmethod
    def _command_evidence_digest(events: list[Mapping[str, Any]]) -> str:
        return canonical_digest(
            [
                {
                    "commandOrdinal": event["commandOrdinal"],
                    "exitCode": event["exitCode"],
                    "exitSha256": event["exitSha256"],
                    "timedOut": event["timedOut"],
                    "truncated": event["truncated"],
                    "stdoutSha256": event["stdoutSha256"],
                    "stderrSha256": event["stderrSha256"],
                    "resultSha256": event["resultSha256"],
                }
                for event in events
            ]
        )

    def _normalize_call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name not in TOOL_NAMES:
            raise ProofPlaneError("unknown broker tool %r" % name)
        _closed_json(arguments, "tool arguments")
        if name == "proof_exec":
            allowed = {"args", "cwd", "environment", "timeoutSeconds"}
            if set(arguments) - allowed or "args" not in arguments:
                raise ProofPlaneError("proof_exec arguments are invalid")
            args = arguments["args"]
            if not isinstance(args, list) or not args or len(args) > 64:
                raise ProofPlaneError("args must contain 1 to 64 argv strings")
            normalized_args: list[str] = []
            for index, item in enumerate(args):
                if not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096:
                    raise ProofPlaneError("args[%d] is invalid" % index)
                normalized_args.append(item)
            if sum(len(item) for item in normalized_args) > 32_768:
                raise ProofPlaneError("command argv exceeds the 32 KiB limit")
            cwd = _guest_relative_path(arguments.get("cwd", "."), "cwd")
            environment = arguments.get("environment", {})
            if not isinstance(environment, Mapping):
                raise ProofPlaneError("command environment must be an object")
            if len(environment) > 64:
                raise ProofPlaneError("command environment exceeds 64 entries")
            normalized_environment: dict[str, str] = {}
            for environment_name, item in sorted(environment.items(), key=lambda pair: str(pair[0])):
                if (
                    not isinstance(environment_name, str)
                    or not ENV_NAME_PATTERN.fullmatch(environment_name)
                    or not isinstance(item, str)
                    or "\x00" in item
                    or len(item) > 4096
                ):
                    raise ProofPlaneError("command environment is invalid")
                normalized_environment[environment_name] = item
            if "timeoutSeconds" in arguments and arguments["timeoutSeconds"] is None:
                raise ProofPlaneError("timeoutSeconds must be omitted to use the broker default")
            timeout = arguments.get("timeoutSeconds", self.config["commandTimeoutSeconds"])
            if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= self.config["commandTimeoutSeconds"]:
                raise ProofPlaneError("timeoutSeconds exceeds the broker limit")
            return {
                "args": normalized_args,
                "cwd": cwd,
                "environment": normalized_environment,
                "timeoutSeconds": timeout,
            }
        if name == "proof_read_file":
            if set(arguments) - {"path", "startLine", "endLine"} or "path" not in arguments:
                raise ProofPlaneError("proof_read_file arguments are invalid")
            path = _guest_relative_path(arguments["path"], "path", allow_root=False)
            start = arguments.get("startLine", 1)
            end = arguments.get("endLine", start + 399 if isinstance(start, int) and not isinstance(start, bool) else 400)
            if (
                not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(end, int)
                or isinstance(end, bool)
                or start < 1
                or end < start
                or end - start >= 400
            ):
                raise ProofPlaneError("read range must contain at most 400 ordered lines")
            return {"path": path, "startLine": start, "endLine": end}
        if name == "proof_apply_patch":
            exact_fields(arguments, ("patch",), "proof_apply_patch")
            patch = arguments["patch"]
            if not isinstance(patch, str) or not patch or len(patch.encode("utf-8")) > 200_000:
                raise ProofPlaneError("patch must contain 1 to 200000 UTF-8 bytes")
            return {"patch": patch}
        if arguments:
            raise ProofPlaneError("proof_git_evidence accepts no arguments")
        return {}

    def _reserve_call(self, name: str, arguments: Mapping[str, Any]) -> tuple[int, str]:
        self.tool_calls = self._restore_tool_calls()
        if self.tool_calls >= self.config["toolCallLimit"]:
            raise ProofPlaneError("broker tool-call limit exceeded")
        ordinal = self.tool_calls + 1
        arguments_sha256 = canonical_digest(arguments)
        environment = arguments.get("environment", {}) if name == "proof_exec" else {}
        effective_timeout = arguments.get("timeoutSeconds", self.config["commandTimeoutSeconds"])
        append_ledger_event(
            Path(self.config["ledgerPath"]),
            {
                "type": "broker-tool-start",
                **self._binding(),
                "toolName": name,
                "toolCallOrdinal": ordinal,
                "argumentsSha256": arguments_sha256,
                "environmentSha256": canonical_digest(environment),
                "effectiveTimeoutSeconds": effective_timeout,
            },
        )
        self.tool_calls = ordinal
        return ordinal, arguments_sha256

    def _record_tool_result(self, name: str, ordinal: int, *, status: str, result_digest: str) -> None:
        self._restore_tool_calls()
        entries = validate_ledger(Path(self.config["ledgerPath"]))
        command_events = [
            dict(entry["event"])
            for entry in entries
            if isinstance(entry["event"], Mapping)
            and entry["event"].get("type") == "broker-command"
            and entry["event"].get("toolCallOrdinal") == ordinal
        ]
        append_ledger_event(
            Path(self.config["ledgerPath"]),
            {
                "type": "broker-tool-result",
                **self._binding(),
                "toolName": name,
                "toolCallOrdinal": ordinal,
                "status": status,
                "resultSha256": result_digest,
                "commandCount": len(command_events),
                "commandEvidenceSha256": self._command_evidence_digest(command_events),
            },
        )

    def _execute_call(self, name: str, arguments: Mapping[str, Any], ordinal: int, arguments_sha256: str) -> dict[str, Any]:
        common = {
            "tool_name": name,
            "tool_call_ordinal": ordinal,
            "arguments_sha256": arguments_sha256,
        }
        if name == "proof_exec":
            return self.runtime.execute(
                arguments["args"],
                cwd=arguments["cwd"],
                environment=arguments["environment"],
                timeout_seconds=arguments["timeoutSeconds"],
                command_ordinal=1,
                **common,
            )
        if name == "proof_read_file":
            return self.runtime.execute(
                ["sed", "-n", "%d,%dp" % (arguments["startLine"], arguments["endLine"]), "--", "./" + arguments["path"]],
                command_ordinal=1,
                **common,
            )
        if name == "proof_apply_patch":
            patch = arguments["patch"]
            checked = self.runtime.execute(
                ["git", "apply", "--check", "--whitespace=error", "-"],
                stdin_text=patch,
                command_ordinal=1,
                **common,
            )
            if checked["returncode"] != 0:
                return {"applied": False, "check": checked}
            applied = self.runtime.execute(
                ["git", "apply", "--whitespace=error", "-"],
                stdin_text=patch,
                command_ordinal=2,
                **common,
            )
            return {"applied": applied["returncode"] == 0, "check": checked, "apply": applied}
        status = self.runtime.execute(["git", "status", "--short"], command_ordinal=1, **common)
        statistics = self.runtime.execute(["git", "diff", "--stat", "--"], command_ordinal=2, **common)
        patch = self.runtime.execute(
            ["git", "diff", "--no-ext-diff", "--binary", "--"],
            command_ordinal=3,
            **common,
        )
        return {"status": status, "statistics": statistics, "patch": patch}

    def tools(self) -> list[dict[str, Any]]:
        return proof_tool_descriptors()

    def call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(name, str) or not isinstance(arguments, Mapping):
            raise ProofPlaneError("tool name and arguments are invalid")
        normalized = self._normalize_call(name, arguments)
        ordinal, arguments_sha256 = self._reserve_call(name, normalized)
        try:
            result = self._execute_call(name, normalized, ordinal, arguments_sha256)
        except Exception as exc:
            error_digest = canonical_digest({"errorType": type(exc).__name__, "message": str(exc)})
            self._record_tool_result(name, ordinal, status="failed", result_digest=error_digest)
            raise
        self._record_tool_result(name, ordinal, status="succeeded", result_digest=canonical_digest(result))
        return result


def _response(identifier: Any, *, result: Any = None, error: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    value: dict[str, Any] = {"jsonrpc": "2.0", "id": identifier}
    if error is not None:
        value["error"] = error
    else:
        value["result"] = result
    return value


def _reject_json_constant(value: str) -> None:
    raise ProofPlaneError("JSON-RPC request contains non-finite number %s" % value)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("JSON-RPC request contains duplicate object key %r" % key)
        value[key] = item
    return value


def _write_response(value: Mapping[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n"
    sys.stdout.write(payload)
    sys.stdout.flush()


def _frames() -> Any:
    """Yield bounded newline-delimited MCP frames without unbounded readline."""

    binary = getattr(sys.stdin, "buffer", None)
    if binary is None:
        for text_frame in sys.stdin:
            raw = text_frame.encode("utf-8")
            yield raw, len(raw) > MCP_FRAME_BYTE_LIMIT
        return
    while True:
        raw = binary.readline(MCP_FRAME_BYTE_LIMIT + 1)
        if not raw:
            return
        oversized = len(raw) > MCP_FRAME_BYTE_LIMIT
        if oversized and not raw.endswith(b"\n"):
            while raw and not raw.endswith(b"\n"):
                raw = binary.readline(MCP_FRAME_BYTE_LIMIT + 1)
        if oversized:
            yield b"", True
        else:
            yield raw, False


def serve(config_path: Path) -> int:
    broker = ProofBroker(load_json(config_path))
    for raw_bytes, oversized in _frames():
        request: Any = {}
        try:
            if oversized:
                raise ProofPlaneError("JSON-RPC request exceeds the 1 MB limit")
            try:
                raw = raw_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ProofPlaneError("JSON-RPC request must be UTF-8") from exc
            request = json.loads(raw, object_pairs_hook=_json_pairs, parse_constant=_reject_json_constant)
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ProofPlaneError("request must be a JSON-RPC 2.0 object")
            _closed_json(request, "JSON-RPC request")
            identifier = request.get("id")
            method = request.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "jstack-proof-broker", "version": BROKER_VERSION},
                }
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                result = {"tools": broker.tools()}
            elif method == "tools/call":
                params = request.get("params", {})
                if not isinstance(params, Mapping):
                    raise ProofPlaneError("tools/call params must be an object")
                arguments = params.get("arguments", {})
                if not isinstance(arguments, Mapping):
                    raise ProofPlaneError("tools/call arguments must be an object")
                output = broker.call(params.get("name"), arguments)
                result = {
                    "content": [{"type": "text", "text": json.dumps(output, sort_keys=True)}],
                    "structuredContent": output,
                    "isError": False,
                }
            else:
                raise ProofPlaneError("unsupported JSON-RPC method")
            _write_response(_response(identifier, result=result))
        except (ProofPlaneError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
            identifier = request.get("id") if isinstance(request, dict) else None
            _write_response(_response(identifier, error={"code": -32602, "message": str(exc)}))
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: python -m tools.proof_plane.broker <config.json>\n")
        return 2
    try:
        return serve(Path(sys.argv[1]))
    except (ProofPlaneError, OSError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
