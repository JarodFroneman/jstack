"""Closed Apple ``container`` bootstrap/freshness lifecycle for Beta.1.

The Proof Plane must not silently adopt an arbitrary per-user Apple container
store.  This module owns one dedicated app root, one fixed 1.2.2 CLI path, and
one canonical start transcript below the repository's private study root.
Production entry points accept only ``repo_root``; command, environment, app
root, install root, clock, and subprocess behavior are not caller-selectable.

The bootstrap receipt proves a trusted maintainer started a previously absent
dedicated root and that the complete inspectable runtime TCB matched
immediately afterward.  It does not widen the assurance scope declared by
``runtime_tcb``: live process identity, per-run helpers, unpacked snapshots,
and the host OS still require the documented operational controls.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import platform
import pwd
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .common import (
    ProofPlaneError,
    _path_lock,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    load_json,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
    utc_now,
)
from .runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
    AppleRuntimeTCB,
    inspect_apple_container_tcb,
    validate_apple_container_tcb_document,
)


RUNTIME_BOOTSTRAP_SCHEMA = "jstack.eval.apple-container-runtime-bootstrap-receipt.v1"
RUNTIME_BOOTSTRAP_CONTRACT = "apple-container-1.2.2-dedicated-fresh-root-v1"
RUNTIME_BOOTSTRAP_STATUS_SCHEMA = "jstack.eval.apple-container-runtime-bootstrap-status.v1"
RUNTIME_BOOTSTRAP_INTENT_SCHEMA = "jstack.eval.apple-container-runtime-bootstrap-intent.v1"
RUNTIME_BOOTSTRAP_PROCESS_SCHEMA = "jstack.eval.apple-container-runtime-bootstrap-process.v1"

_PRIVATE_STUDY_RELATIVE = Path(".jstack-evals/beta1-codex-proof-study")
_EVIDENCE_DIRECTORY_NAME = "runtime-bootstrap"
_INTENT_NAME = "start-intent.json"
_PROCESS_NAME = "start-process.json"
_RECEIPT_NAME = "runtime-bootstrap-receipt.json"
_LOCK_NAME = "runtime-bootstrap-lifecycle"
_RUNTIME = Path("/usr/local/bin/container")
_INSTALL_ROOT = Path("/usr/local")
_APP_ROOT_SUFFIX = Path(
    "Library/Application Support/com.apple.container.jstack-beta1-codex-proof-study"
)
_INSTALL_CONFIG = _INSTALL_ROOT / "etc/container/config.toml"
_USER_CONFIG_SUFFIX = Path(".config/container/config.toml")
_MAX_PROCESS_OUTPUT = 5_000_000
_MAX_DOCUMENT_BYTES = 20_000_000
_SHA256_LENGTH = 64


@dataclass(frozen=True)
class RuntimeBootstrapPaths:
    repo_root: Path
    private_study_root: Path
    evidence_root: Path
    intent: Path
    process: Path
    receipt: Path
    lock: Path
    runtime: Path
    install_root: Path
    app_root: Path
    user_config: Path


def _repo_root(repo_root: Path) -> Path:
    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("repo_root must be an absolute non-symlink directory")
    return repo_root.resolve()


def _account_home() -> Path:
    if os.name != "posix":
        raise ProofPlaneError("Apple runtime bootstrap requires a POSIX account")
    try:
        raw = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError) as exc:
        raise ProofPlaneError("current account home directory is unavailable") from exc
    home = Path(raw)
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        raise ProofPlaneError("current account home must be an absolute directory")
    try:
        metadata = home.lstat()
    except OSError as exc:
        raise ProofPlaneError("current account home is unavailable") from exc
    if os.name == "posix" and metadata.st_uid != os.getuid():
        raise ProofPlaneError("current account home must be owned by the current account")
    return home.resolve()


def beta1_runtime_bootstrap_paths(repo_root: Path) -> RuntimeBootstrapPaths:
    """Derive every fixed path without creating or changing anything."""

    root = _repo_root(repo_root)
    private = root / _PRIVATE_STUDY_RELATIVE
    evidence = private / _EVIDENCE_DIRECTORY_NAME
    app_root = _account_home() / _APP_ROOT_SUFFIX
    return RuntimeBootstrapPaths(
        repo_root=root,
        private_study_root=private,
        evidence_root=evidence,
        intent=evidence / _INTENT_NAME,
        process=evidence / _PROCESS_NAME,
        receipt=evidence / _RECEIPT_NAME,
        lock=private / _LOCK_NAME,
        runtime=_RUNTIME,
        install_root=_INSTALL_ROOT,
        app_root=app_root,
        user_config=_account_home() / _USER_CONFIG_SUFFIX,
    )


def _require_safe_app_root_ancestry(paths: RuntimeBootstrapPaths) -> None:
    """Reject redirected or foreign-owned parents before Apple creates appRoot."""

    home = _account_home()
    try:
        relative_parent = paths.app_root.parent.relative_to(home)
    except ValueError as exc:
        raise ProofPlaneError("dedicated Beta.1 app root escapes the account home") from exc
    current = home
    for part in relative_parent.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ProofPlaneError(
                "dedicated Beta.1 app-root parent must already exist"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (os.name == "posix" and metadata.st_uid != os.getuid())
        ):
            raise ProofPlaneError(
                "dedicated Beta.1 app-root parents must be user-owned non-symlink directories"
            )


def _private_directory(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is absent" % field) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (os.name == "posix" and metadata.st_uid != os.getuid())
    ):
        raise ProofPlaneError("%s must be a user-owned mode-0700 directory" % field)
    return path.resolve()


def _private_file(path: Path, field: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is absent" % field) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or (os.name == "posix" and metadata.st_uid != os.getuid())
    ):
        raise ProofPlaneError("%s must be a user-owned mode-0600 regular file" % field)
    return read_bounded_regular_bytes(
        path, maximum_bytes=_MAX_DOCUMENT_BYTES, field=field
    )


def _canonical_file(path: Path, field: str) -> Tuple[Dict[str, Any], bytes]:
    raw = _private_file(path, field)
    value = load_json(path, maximum_bytes=_MAX_DOCUMENT_BYTES)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    normalized = dict(value)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return normalized, raw


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _parsed_timestamp(value: Any, field: str) -> dt.datetime:
    normalized = rfc3339_timestamp(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)


def _require_chronology(
    earlier: Any, later: Any, field: str
) -> None:
    if _parsed_timestamp(later, field + " later") < _parsed_timestamp(
        earlier, field + " earlier"
    ):
        raise ProofPlaneError("%s chronology is reversed" % field)


def _process_capture(value: Any, field: str, *, require_success: bool) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(
        value,
        ("returnCode", "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes"),
        field,
    )
    return_code = value["returnCode"]
    if (
        not isinstance(return_code, int)
        or isinstance(return_code, bool)
        or return_code < -255
        or return_code > 255
        or (require_success and return_code != 0)
    ):
        raise ProofPlaneError("%s returnCode is invalid" % field)
    normalized: Dict[str, Any] = {"returnCode": return_code}
    total = 0
    for stream in ("stdout", "stderr"):
        digest = _sha256(value[stream + "Sha256"], field + " " + stream + "Sha256")
        count = value[stream + "Bytes"]
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            or count > _MAX_PROCESS_OUTPUT
        ):
            raise ProofPlaneError("%s %sBytes is invalid" % (field, stream))
        normalized[stream + "Sha256"] = digest
        normalized[stream + "Bytes"] = count
        total += count
    if total > _MAX_PROCESS_OUTPUT:
        raise ProofPlaneError("%s exceeds the combined output limit" % field)
    return normalized


def _capture(result: subprocess.CompletedProcess) -> Dict[str, Any]:
    stdout = bytes(result.stdout)
    stderr = bytes(result.stderr)
    return {
        "returnCode": int(result.returncode),
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stdoutBytes": len(stdout),
        "stderrSha256": hashlib.sha256(stderr).hexdigest(),
        "stderrBytes": len(stderr),
    }


def _environment() -> Dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(_account_home()),
    }


def _kill(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - this lifecycle is macOS-only.
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _run_command(
    argv: Sequence[str], *, timeout_seconds: int
) -> subprocess.CompletedProcess:
    if (
        isinstance(argv, (str, bytes, bytearray))
        or not isinstance(argv, Sequence)
        or not 1 <= len(argv) <= 16
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 4096
            or any(character in item for character in ("\x00", "\r", "\n"))
            for item in argv
        )
    ):
        raise ProofPlaneError("Apple runtime bootstrap argv is invalid")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 180:
        raise ProofPlaneError("Apple runtime bootstrap timeout is invalid")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                tuple(argv),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=_environment(),
                cwd="/",
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise ProofPlaneError("Apple runtime bootstrap command could not start") from exc
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _kill(process)
            process.wait()
            raise ProofPlaneError("Apple runtime bootstrap command timed out") from exc
        stdout_file.flush()
        stderr_file.flush()
        if stdout_file.tell() + stderr_file.tell() > _MAX_PROCESS_OUTPUT:
            raise ProofPlaneError("Apple runtime bootstrap command output exceeded its limit")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return subprocess.CompletedProcess(
            tuple(argv), return_code, stdout_file.read(), stderr_file.read()
        )


def _runtime_file(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("signed Apple container 1.2.2 is not installed") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(path, os.X_OK)
    ):
        raise ProofPlaneError("Apple container runtime must be the fixed regular executable")
    return path


def _platform_guard() -> None:
    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise ProofPlaneError("Apple runtime bootstrap requires arm64 macOS")
    if os.geteuid() == 0:
        raise ProofPlaneError("Apple runtime bootstrap must run as the maintainer account, not root")


def _start_argv(paths: RuntimeBootstrapPaths) -> Tuple[str, ...]:
    return (
        str(paths.runtime),
        "system",
        "start",
        "--app-root",
        str(paths.app_root),
        "--install-root",
        str(paths.install_root),
        "--enable-kernel-install",
        "--timeout",
        "120",
    )


def _status_argv(paths: RuntimeBootstrapPaths) -> Tuple[str, ...]:
    return (str(paths.runtime), "system", "status", "--format", "json")


def _intent_body(paths: RuntimeBootstrapPaths, preflight: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schemaVersion": RUNTIME_BOOTSTRAP_INTENT_SCHEMA,
        "contractVersion": RUNTIME_BOOTSTRAP_CONTRACT,
        "runtimePath": str(paths.runtime),
        "installRoot": str(paths.install_root),
        "appRoot": str(paths.app_root),
        "preflightStatusCommandSha256": canonical_digest(list(_status_argv(paths))),
        "preflightStatusProcess": dict(preflight),
        "freshAppRootAbsentBeforeStart": True,
        "installConfigAbsentBeforeStart": True,
        "userConfigAbsentBeforeStart": True,
        "createdAt": utc_now(),
    }


def validate_runtime_bootstrap_intent(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("runtime bootstrap intent must be an object")
    exact_fields(
        value,
        (
            "schemaVersion", "contractVersion", "runtimePath", "installRoot",
            "appRoot", "preflightStatusCommandSha256", "preflightStatusProcess",
            "freshAppRootAbsentBeforeStart", "installConfigAbsentBeforeStart",
            "userConfigAbsentBeforeStart", "createdAt", "intentSha256",
        ),
        "runtime bootstrap intent",
    )
    if value["schemaVersion"] != RUNTIME_BOOTSTRAP_INTENT_SCHEMA:
        raise ProofPlaneError("runtime bootstrap intent schema is unsupported")
    if value["contractVersion"] != RUNTIME_BOOTSTRAP_CONTRACT:
        raise ProofPlaneError("runtime bootstrap intent contract is unsupported")
    for name in ("runtimePath", "installRoot", "appRoot"):
        item = value[name]
        if not isinstance(item, str) or not Path(item).is_absolute() or len(item) > 4096:
            raise ProofPlaneError("runtime bootstrap intent %s is invalid" % name)
    if value["runtimePath"] != str(_RUNTIME) or value["installRoot"] != str(_INSTALL_ROOT):
        raise ProofPlaneError("runtime bootstrap intent uses a non-fixed installation")
    expected_app = str(_account_home() / _APP_ROOT_SUFFIX)
    if value["appRoot"] != expected_app:
        raise ProofPlaneError("runtime bootstrap intent uses a non-dedicated app root")
    _sha256(value["preflightStatusCommandSha256"], "preflight status command digest")
    expected_status_command = canonical_digest(
        [str(_RUNTIME), "system", "status", "--format", "json"]
    )
    if value["preflightStatusCommandSha256"] != expected_status_command:
        raise ProofPlaneError("runtime bootstrap preflight command differs")
    preflight = _process_capture(
        value["preflightStatusProcess"],
        "runtime bootstrap preflight status process",
        require_success=False,
    )
    if preflight["returnCode"] == 0:
        raise ProofPlaneError("runtime bootstrap cannot adopt an already-running service")
    if value["freshAppRootAbsentBeforeStart"] is not True:
        raise ProofPlaneError("runtime bootstrap requires a previously absent app root")
    if value["installConfigAbsentBeforeStart"] is not True:
        raise ProofPlaneError("runtime bootstrap requires no install-level config override")
    if value["userConfigAbsentBeforeStart"] is not True:
        raise ProofPlaneError("runtime bootstrap requires no account-level config override")
    created_at = rfc3339_timestamp(value["createdAt"], "runtime bootstrap createdAt")
    body = {key: item for key, item in value.items() if key != "intentSha256"}
    if value["intentSha256"] != canonical_digest(body):
        raise ProofPlaneError("runtime bootstrap intent self-digest mismatch")
    return {
        **body,
        "preflightStatusProcess": preflight,
        "createdAt": created_at,
        "intentSha256": value["intentSha256"],
    }


def validate_runtime_bootstrap_process(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("runtime bootstrap process receipt must be an object")
    exact_fields(
        value,
        ("schemaVersion", "intentRawSha256", "intentSha256", "commandSha256", "process", "completedAt", "processSha256"),
        "runtime bootstrap process receipt",
    )
    if value["schemaVersion"] != RUNTIME_BOOTSTRAP_PROCESS_SCHEMA:
        raise ProofPlaneError("runtime bootstrap process schema is unsupported")
    for name in ("intentRawSha256", "intentSha256", "commandSha256"):
        _sha256(value[name], "runtime bootstrap process " + name)
    process = _process_capture(
        value["process"], "runtime bootstrap start process", require_success=True
    )
    completed_at = rfc3339_timestamp(value["completedAt"], "runtime bootstrap completedAt")
    body = {key: item for key, item in value.items() if key != "processSha256"}
    if value["processSha256"] != canonical_digest(body):
        raise ProofPlaneError("runtime bootstrap process self-digest mismatch")
    return {
        **body,
        "process": process,
        "completedAt": completed_at,
        "processSha256": value["processSha256"],
    }


def validate_runtime_bootstrap_receipt(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("runtime bootstrap receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion", "contractVersion", "intentRawSha256", "intentSha256",
            "processRawSha256", "processSha256", "runtimePath", "installRoot",
            "appRoot", "startCommandSha256", "runtimeTcb", "observedAt",
            "receiptSha256",
        ),
        "runtime bootstrap receipt",
    )
    if value["schemaVersion"] != RUNTIME_BOOTSTRAP_SCHEMA:
        raise ProofPlaneError("runtime bootstrap receipt schema is unsupported")
    if value["contractVersion"] != RUNTIME_BOOTSTRAP_CONTRACT:
        raise ProofPlaneError("runtime bootstrap receipt contract is unsupported")
    for name in ("intentRawSha256", "intentSha256", "processRawSha256", "processSha256", "startCommandSha256"):
        _sha256(value[name], "runtime bootstrap receipt " + name)
    if value["runtimePath"] != str(_RUNTIME) or value["installRoot"] != str(_INSTALL_ROOT):
        raise ProofPlaneError("runtime bootstrap receipt uses a non-fixed installation")
    expected_app = str(_account_home() / _APP_ROOT_SUFFIX)
    if value["appRoot"] != expected_app:
        raise ProofPlaneError("runtime bootstrap receipt uses a non-dedicated app root")
    expected_command = canonical_digest(
        [
            str(_RUNTIME), "system", "start", "--app-root", expected_app,
            "--install-root", str(_INSTALL_ROOT), "--enable-kernel-install",
            "--timeout", "120",
        ]
    )
    if value["startCommandSha256"] != expected_command:
        raise ProofPlaneError("runtime bootstrap start command differs")
    runtime_tcb = validate_apple_container_tcb_document(value["runtimeTcb"])
    status = runtime_tcb["statusQuery"]["status"]
    if status["appRoot"] != expected_app or status["installRoot"] != str(_INSTALL_ROOT):
        raise ProofPlaneError("runtime bootstrap TCB differs from the dedicated roots")
    if runtime_tcb["runtime"]["version"] != "1.2.2":
        raise ProofPlaneError("runtime bootstrap TCB differs from Apple container 1.2.2")
    observed_at = rfc3339_timestamp(value["observedAt"], "runtime bootstrap observedAt")
    body = {key: item for key, item in value.items() if key != "receiptSha256"}
    if value["receiptSha256"] != canonical_digest(body):
        raise ProofPlaneError("runtime bootstrap receipt self-digest mismatch")
    return {
        **body,
        "runtimeTcb": runtime_tcb,
        "observedAt": observed_at,
        "receiptSha256": value["receiptSha256"],
    }


def _load_chain(paths: RuntimeBootstrapPaths) -> Tuple[Dict[str, Any], bytes, Dict[str, Any], bytes]:
    intent_value, intent_raw = _canonical_file(paths.intent, "runtime bootstrap intent")
    intent = validate_runtime_bootstrap_intent(intent_value)
    process_value, process_raw = _canonical_file(paths.process, "runtime bootstrap process receipt")
    process = validate_runtime_bootstrap_process(process_value)
    if process["intentRawSha256"] != hashlib.sha256(intent_raw).hexdigest():
        raise ProofPlaneError("runtime bootstrap process differs from its intent bytes")
    if process["intentSha256"] != intent["intentSha256"]:
        raise ProofPlaneError("runtime bootstrap process differs from its intent")
    expected_command = canonical_digest(list(_start_argv(paths)))
    if process["commandSha256"] != expected_command:
        raise ProofPlaneError("runtime bootstrap process command differs")
    _require_chronology(
        intent["createdAt"],
        process["completedAt"],
        "runtime bootstrap intent/process",
    )
    return intent, intent_raw, process, process_raw


def _receipt_from_chain(
    paths: RuntimeBootstrapPaths,
    intent: Mapping[str, Any],
    intent_raw: bytes,
    process: Mapping[str, Any],
    process_raw: bytes,
    runtime_tcb: AppleRuntimeTCB,
) -> Dict[str, Any]:
    document = dict(runtime_tcb.document)
    status = document["statusQuery"]["status"]
    if status["appRoot"] != str(paths.app_root):
        raise ProofPlaneError("live Apple runtime does not use the dedicated Beta.1 app root")
    if status["installRoot"] != str(paths.install_root):
        raise ProofPlaneError("live Apple runtime does not use the fixed install root")
    observed_at = utc_now()
    _require_chronology(
        process["completedAt"],
        observed_at,
        "runtime bootstrap process/receipt",
    )
    body = {
        "schemaVersion": RUNTIME_BOOTSTRAP_SCHEMA,
        "contractVersion": RUNTIME_BOOTSTRAP_CONTRACT,
        "intentRawSha256": hashlib.sha256(intent_raw).hexdigest(),
        "intentSha256": intent["intentSha256"],
        "processRawSha256": hashlib.sha256(process_raw).hexdigest(),
        "processSha256": process["processSha256"],
        "runtimePath": str(paths.runtime),
        "installRoot": str(paths.install_root),
        "appRoot": str(paths.app_root),
        "startCommandSha256": canonical_digest(list(_start_argv(paths))),
        "runtimeTcb": document,
        "observedAt": observed_at,
    }
    return validate_runtime_bootstrap_receipt(
        {**body, "receiptSha256": canonical_digest(body)}
    )


def _validate_receipt_process_join(
    receipt: Mapping[str, Any], process: Mapping[str, Any]
) -> None:
    _require_chronology(
        process["completedAt"],
        receipt["observedAt"],
        "runtime bootstrap process/receipt",
    )


def _publish(path: Path, value: Mapping[str, Any]) -> None:
    atomic_publish_bytes_once(path, canonical_bytes(dict(value)) + b"\n", mode=0o600)


def _create_evidence_root(paths: RuntimeBootstrapPaths) -> None:
    _private_directory(paths.private_study_root, "private Beta.1 study root")
    if paths.evidence_root.exists() or paths.evidence_root.is_symlink():
        _private_directory(paths.evidence_root, "runtime bootstrap evidence root")
        return
    try:
        paths.evidence_root.mkdir(mode=0o700)
        os.chmod(paths.evidence_root, 0o700)
    except OSError as exc:
        raise ProofPlaneError("runtime bootstrap evidence root could not be created") from exc
    _private_directory(paths.evidence_root, "runtime bootstrap evidence root")


def _exact_evidence_children(paths: RuntimeBootstrapPaths) -> Tuple[str, ...]:
    try:
        children = tuple(paths.evidence_root.iterdir())
    except OSError as exc:
        raise ProofPlaneError("runtime bootstrap evidence root cannot be read") from exc
    allowed = {_INTENT_NAME, _PROCESS_NAME, _RECEIPT_NAME}
    if any(child.name not in allowed for child in children):
        raise ProofPlaneError("runtime bootstrap evidence root contains an unexpected entry")
    return tuple(sorted(child.name for child in children))


def inspect_beta1_runtime_bootstrap(repo_root: Path) -> Dict[str, Any]:
    """Return truthful, read-only bootstrap status; never create files or run start."""

    paths = beta1_runtime_bootstrap_paths(repo_root)
    installed = False
    try:
        _runtime_file(paths.runtime)
        installed = True
    except ProofPlaneError:
        pass
    if not paths.evidence_root.exists() and not paths.evidence_root.is_symlink():
        return {
            "schemaVersion": RUNTIME_BOOTSTRAP_STATUS_SCHEMA,
            "state": "not-started",
            "runtimeInstalled": installed,
            "runtimePath": str(paths.runtime),
            "appRoot": str(paths.app_root),
            "receiptSha256": None,
            "runtimeTcbSha256": None,
            "ready": False,
            "recoveryRequired": False,
            "error": None,
            "mutated": False,
        }
    error: Optional[str] = None
    state = "invalid"
    receipt_sha256: Optional[str] = None
    tcb_sha256: Optional[str] = None
    recovery_required = False
    try:
        _private_directory(paths.evidence_root, "runtime bootstrap evidence root")
        children = _exact_evidence_children(paths)
        if children == (_INTENT_NAME,):
            value, _raw = _canonical_file(paths.intent, "runtime bootstrap intent")
            validate_runtime_bootstrap_intent(value)
            state = "start-interrupted-before-process-receipt"
            recovery_required = True
        elif children == tuple(sorted((_INTENT_NAME, _PROCESS_NAME))):
            _load_chain(paths)
            state = "recovery-ready"
            recovery_required = True
        elif children == tuple(sorted((_INTENT_NAME, _PROCESS_NAME, _RECEIPT_NAME))):
            intent, intent_raw, process, process_raw = _load_chain(paths)
            receipt_value, _receipt_raw = _canonical_file(paths.receipt, "runtime bootstrap receipt")
            receipt = validate_runtime_bootstrap_receipt(receipt_value)
            if receipt["intentRawSha256"] != hashlib.sha256(intent_raw).hexdigest() or receipt["intentSha256"] != intent["intentSha256"]:
                raise ProofPlaneError("runtime bootstrap receipt differs from its intent")
            if receipt["processRawSha256"] != hashlib.sha256(process_raw).hexdigest() or receipt["processSha256"] != process["processSha256"]:
                raise ProofPlaneError("runtime bootstrap receipt differs from its process")
            _validate_receipt_process_join(receipt, process)
            _platform_guard()
            _runtime_file(paths.runtime)
            live = inspect_apple_container_tcb(paths.runtime)
            if dict(live.document) != receipt["runtimeTcb"]:
                raise ProofPlaneError(
                    "live Apple runtime TCB differs from its dedicated bootstrap receipt"
                )
            receipt_sha256 = receipt["receiptSha256"]
            tcb_sha256 = live.tcb_sha256
            state = "ready"
        else:
            raise ProofPlaneError("runtime bootstrap evidence is partial or reordered")
    except ProofPlaneError as exc:
        error = str(exc)
        state = "invalid"
        recovery_required = True
    return {
        "schemaVersion": RUNTIME_BOOTSTRAP_STATUS_SCHEMA,
        "state": state,
        "runtimeInstalled": installed,
        "runtimePath": str(paths.runtime),
        "appRoot": str(paths.app_root),
        "receiptSha256": receipt_sha256,
        "runtimeTcbSha256": tcb_sha256,
        "ready": state == "ready",
        "recoveryRequired": recovery_required,
        "error": error,
        "mutated": False,
    }


def require_beta1_runtime_bootstrap(repo_root: Path) -> AppleRuntimeTCB:
    """Reinspect and require exact equality with the fixed bootstrap receipt."""

    paths = beta1_runtime_bootstrap_paths(repo_root)
    _platform_guard()
    _runtime_file(paths.runtime)
    _private_directory(paths.evidence_root, "runtime bootstrap evidence root")
    if _exact_evidence_children(paths) != tuple(
        sorted((_INTENT_NAME, _PROCESS_NAME, _RECEIPT_NAME))
    ):
        raise ProofPlaneError("complete runtime bootstrap evidence is absent")
    intent, intent_raw, process, process_raw = _load_chain(paths)
    receipt_value, _raw = _canonical_file(paths.receipt, "runtime bootstrap receipt")
    receipt = validate_runtime_bootstrap_receipt(receipt_value)
    if receipt["intentRawSha256"] != hashlib.sha256(intent_raw).hexdigest() or receipt["intentSha256"] != intent["intentSha256"]:
        raise ProofPlaneError("runtime bootstrap receipt differs from its intent")
    if receipt["processRawSha256"] != hashlib.sha256(process_raw).hexdigest() or receipt["processSha256"] != process["processSha256"]:
        raise ProofPlaneError("runtime bootstrap receipt differs from its process")
    _validate_receipt_process_join(receipt, process)
    live = inspect_apple_container_tcb(paths.runtime)
    if dict(live.document) != receipt["runtimeTcb"]:
        raise ProofPlaneError("live Apple runtime TCB differs from its dedicated bootstrap receipt")
    return live


def start_beta1_runtime_bootstrap(repo_root: Path) -> Dict[str, Any]:
    """Start exactly one fresh dedicated runtime and publish its evidence chain."""

    paths = beta1_runtime_bootstrap_paths(repo_root)
    _platform_guard()
    _runtime_file(paths.runtime)
    with _path_lock(paths.lock):
        _create_evidence_root(paths)
        children = _exact_evidence_children(paths)
        if children:
            raise ProofPlaneError("runtime bootstrap already started; use status or recover")
        if paths.app_root.exists() or paths.app_root.is_symlink():
            raise ProofPlaneError("dedicated Beta.1 app root must be absent before first start")
        _require_safe_app_root_ancestry(paths)
        if _INSTALL_CONFIG.exists() or _INSTALL_CONFIG.is_symlink():
            raise ProofPlaneError("install-level Apple container config must be absent before first start")
        if paths.user_config.exists() or paths.user_config.is_symlink():
            raise ProofPlaneError("account-level Apple container config must be absent before first start")
        preflight_result = _run_command(_status_argv(paths), timeout_seconds=30)
        preflight = _capture(preflight_result)
        if preflight["returnCode"] == 0:
            raise ProofPlaneError("Apple container is already running and cannot be adopted")
        intent_body = _intent_body(paths, preflight)
        intent = validate_runtime_bootstrap_intent(
            {**intent_body, "intentSha256": canonical_digest(intent_body)}
        )
        _publish(paths.intent, intent)
        intent_raw = _private_file(paths.intent, "runtime bootstrap intent")
        start_result = _run_command(_start_argv(paths), timeout_seconds=180)
        process_body = {
            "schemaVersion": RUNTIME_BOOTSTRAP_PROCESS_SCHEMA,
            "intentRawSha256": hashlib.sha256(intent_raw).hexdigest(),
            "intentSha256": intent["intentSha256"],
            "commandSha256": canonical_digest(list(_start_argv(paths))),
            "process": _capture(start_result),
            "completedAt": utc_now(),
        }
        process = validate_runtime_bootstrap_process(
            {**process_body, "processSha256": canonical_digest(process_body)}
        )
        _publish(paths.process, process)
        process_raw = _private_file(paths.process, "runtime bootstrap process receipt")
        runtime_tcb = inspect_apple_container_tcb(paths.runtime)
        receipt = _receipt_from_chain(
            paths, intent, intent_raw, process, process_raw, runtime_tcb
        )
        _publish(paths.receipt, receipt)
        require_beta1_runtime_bootstrap(paths.repo_root)
    return {
        "schemaVersion": RUNTIME_BOOTSTRAP_STATUS_SCHEMA,
        "state": "ready",
        "runtimePath": str(paths.runtime),
        "appRoot": str(paths.app_root),
        "receiptSha256": receipt["receiptSha256"],
        "runtimeTcbSha256": receipt["runtimeTcb"]["tcbSha256"],
        "ready": True,
        "recovered": False,
        "mutated": True,
    }


def recover_beta1_runtime_bootstrap(repo_root: Path) -> Dict[str, Any]:
    """Finish receipt publication only after a complete successful start transcript."""

    paths = beta1_runtime_bootstrap_paths(repo_root)
    _platform_guard()
    _runtime_file(paths.runtime)
    with _path_lock(paths.lock):
        _private_directory(paths.evidence_root, "runtime bootstrap evidence root")
        children = _exact_evidence_children(paths)
        if children == tuple(sorted((_INTENT_NAME, _PROCESS_NAME, _RECEIPT_NAME))):
            live = require_beta1_runtime_bootstrap(paths.repo_root)
            receipt_value, _raw = _canonical_file(paths.receipt, "runtime bootstrap receipt")
            receipt = validate_runtime_bootstrap_receipt(receipt_value)
            return {
                "schemaVersion": RUNTIME_BOOTSTRAP_STATUS_SCHEMA,
                "state": "ready",
                "runtimePath": str(paths.runtime),
                "appRoot": str(paths.app_root),
                "receiptSha256": receipt["receiptSha256"],
                "runtimeTcbSha256": live.tcb_sha256,
                "ready": True,
                "recovered": False,
                "mutated": False,
            }
        if children != tuple(sorted((_INTENT_NAME, _PROCESS_NAME))):
            raise ProofPlaneError(
                "runtime bootstrap recovery requires exact intent and successful process evidence"
            )
        intent, intent_raw, process, process_raw = _load_chain(paths)
        runtime_tcb = inspect_apple_container_tcb(paths.runtime)
        receipt = _receipt_from_chain(
            paths, intent, intent_raw, process, process_raw, runtime_tcb
        )
        _publish(paths.receipt, receipt)
        require_beta1_runtime_bootstrap(paths.repo_root)
    return {
        "schemaVersion": RUNTIME_BOOTSTRAP_STATUS_SCHEMA,
        "state": "ready",
        "runtimePath": str(paths.runtime),
        "appRoot": str(paths.app_root),
        "receiptSha256": receipt["receiptSha256"],
        "runtimeTcbSha256": receipt["runtimeTcb"]["tcbSha256"],
        "ready": True,
        "recovered": True,
        "mutated": True,
    }


__all__ = [
    "RUNTIME_BOOTSTRAP_CONTRACT",
    "RUNTIME_BOOTSTRAP_SCHEMA",
    "RUNTIME_BOOTSTRAP_STATUS_SCHEMA",
    "RuntimeBootstrapPaths",
    "beta1_runtime_bootstrap_paths",
    "inspect_beta1_runtime_bootstrap",
    "recover_beta1_runtime_bootstrap",
    "require_beta1_runtime_bootstrap",
    "start_beta1_runtime_bootstrap",
    "validate_runtime_bootstrap_intent",
    "validate_runtime_bootstrap_process",
    "validate_runtime_bootstrap_receipt",
]
