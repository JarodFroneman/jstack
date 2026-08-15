"""Fail-closed Apple ``container`` trust-boundary inspection for Beta.1.

Apple container 1.2.2 is not one executable.  A scored ``container run`` is
implemented by the CLI, a long-lived API server, installed service plugins, a
locally managed Linux kernel, and a VM-init OCI image.  This module snapshots
the inspectable, on-disk portion of that boundary without installing, starting,
pulling, or tagging anything.  It explicitly does not claim that a previously
started daemon or mutable, unpacked VM snapshot still derives from those bytes.

The public inspector deliberately has no runner, environment, clock, or path
override seam.  Tests patch the private ``_run_command`` function.  Production
callers therefore either obtain one canonical, self-digested snapshot or fail
before a candidate/model process is admitted.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import plistlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    read_bounded_regular_bytes,
)


APPLE_RUNTIME_TCB_SCHEMA = "jstack.eval.apple-container-runtime-tcb.v1"
APPLE_RUNTIME_TCB_CONTRACT = "apple-container-1.2.2-host-tcb-v1"
APPLE_RUNTIME_VERSION = "1.2.2"

_CODESIGN = Path("/usr/bin/codesign")
_TEAM_ID = "UPBK2H6LZM"
_AUTHORITY = "Developer ID Application: Apple Inc. - Containerization (UPBK2H6LZM)"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CDHASH = re.compile(r"^[0-9a-f]{40}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,999}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+/-]{0,255}$")
_MAX_COMMAND_OUTPUT = 2_000_000
_MAX_RUNTIME_FILE_BYTES = 500_000_000
_MAX_CONFIG_BYTES = 2_000_000
_MAX_STATE_BYTES = 20_000_000
_MAX_OCI_BLOB_BYTES = 4_000_000_000
_MAX_OCI_BLOBS = 512
_MAX_OCI_TOTAL_BYTES = 20_000_000_000

_ASSURANCE_SCOPE = {
    "onDiskRuntimeComponents": "byte-and-apple-codesign-bound",
    "effectiveConfiguration": "live-daemon-self-report-and-config-layer-byte-bound",
    "ociContentStore": "descriptor-and-blob-closure-bound",
    "liveDaemonProcesses": "not-attested-requires-controlled-restart",
    "persistentServiceDefinitions": "three-baseline-plists-byte-and-safe-semantics-bound",
    "perRunRuntimeLinuxService": "not-attested-requires-post-creation-plist-and-process-check",
    "unpackedSnapshots": "not-attested-requires-fresh-dedicated-store",
    "hostOperatingSystem": "trusted-outside-proof-plane",
}

# These are every code/config/resource byte shipped by Apple's 1.2.2 package
# that can participate in the CLI/API/plugin path.  Update/uninstall scripts do
# not execute on a run and are intentionally outside the runtime TCB.
_INSTALLED_FILES: Mapping[str, Optional[str]] = {
    "bin/container": "com.apple.container.cli",
    "bin/container-apiserver": "com.apple.container.apiserver",
    "libexec/container/plugins/container-core-images/bin/container-core-images": (
        "com.apple.container.container-core-images"
    ),
    "libexec/container/plugins/container-core-images/config.toml": None,
    "libexec/container/plugins/container-network-vmnet/bin/container-network-vmnet": (
        "com.apple.container.container-network-vmnet"
    ),
    "libexec/container/plugins/container-network-vmnet/config.toml": None,
    "libexec/container/plugins/container-runtime-linux/bin/container-runtime-linux": (
        "com.apple.container.container-runtime-linux"
    ),
    "libexec/container/plugins/container-runtime-linux/config.toml": None,
    "libexec/container/plugins/k8s/bin/k8s": "com.apple.container.k8s",
    "libexec/container/plugins/k8s/config.toml": None,
    "libexec/container/plugins/k8s/resources/kindnet.yaml": None,
    "libexec/container/plugins/machine-apiserver/bin/machine-apiserver": (
        "com.apple.container.machine-apiserver"
    ),
    "libexec/container/plugins/machine-apiserver/config.toml": None,
    "libexec/container/plugins/machine-apiserver/resources/create-user.sh": None,
    "libexec/container/plugins/machine-apiserver/resources/init": None,
}

_PLUGIN_ROOT = "libexec/container/plugins"
_PLUGIN_DIRECTORIES = frozenset(
    str(Path(relative).parent)
    for relative in _INSTALLED_FILES
    if relative.startswith(_PLUGIN_ROOT + "/")
) | frozenset((_PLUGIN_ROOT,))

_INDEX_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
_MANIFEST_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


@dataclass(frozen=True)
class AppleRuntimeTCB:
    """Canonical host TCB plus values required by a fixed run invocation."""

    document: Mapping[str, Any]
    tcb_sha256: str
    runtime_version: str
    runtime_binary_sha256: str
    kernel_path: str
    kernel_sha256: str
    immutable_init_image_reference: str


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofPlaneError("Apple runtime JSON contains duplicate key %r" % key)
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ProofPlaneError("Apple runtime JSON contains non-finite value %s" % value)


def _json(raw: bytes, field: str, maximum: int = _MAX_COMMAND_OUTPUT) -> Any:
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise ProofPlaneError("%s exceeds the closed JSON limit" % field)
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, ValueError, RecursionError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s is not bounded UTF-8 JSON" % field) from exc


def _validate_argv(argv: Sequence[str]) -> Tuple[str, ...]:
    if (
        isinstance(argv, (str, bytes, bytearray))
        or not isinstance(argv, Sequence)
        or not 1 <= len(argv) <= 32
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 4096
            or any(character in item for character in ("\x00", "\r", "\n"))
            for item in argv
        )
    ):
        raise ProofPlaneError("Apple runtime inspection argv is invalid")
    return tuple(argv)


def _environment() -> Dict[str, str]:
    value = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    home = os.environ.get("HOME")
    if (
        isinstance(home, str)
        and home.startswith("/")
        and len(home) <= 4096
        and not any(ord(character) < 32 or ord(character) == 127 for character in home)
    ):
        value["HOME"] = home
    return value


def _kill(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - production TCB inspection is macOS-only.
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _run_command(
    argv: Sequence[str], *, timeout_seconds: int, maximum_output_bytes: int
) -> subprocess.CompletedProcess:
    command = _validate_argv(argv)
    if not 1 <= timeout_seconds <= 120:
        raise ProofPlaneError("Apple runtime inspection timeout is invalid")
    if not 1024 <= maximum_output_bytes <= _MAX_COMMAND_OUTPUT:
        raise ProofPlaneError("Apple runtime inspection output limit is invalid")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                env=_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProofPlaneError("Apple runtime inspection command could not start") from exc
        deadline = time.monotonic() + timeout_seconds
        failure: Optional[str] = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "Apple runtime inspection command timed out"
                break
            if os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size > maximum_output_bytes:
                failure = "Apple runtime inspection command exceeded its output limit"
                break
            time.sleep(0.02)
        if failure is not None:
            _kill(process)
        process.wait(timeout=5)
        size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
        if failure is not None or size > maximum_output_bytes:
            raise ProofPlaneError(failure or "Apple runtime inspection command exceeded its output limit")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return subprocess.CompletedProcess(
            command, int(process.returncode), stdout_file.read(), stderr_file.read()
        )


def _capture(result: subprocess.CompletedProcess) -> Dict[str, Any]:
    return {
        "returnCode": int(result.returncode),
        "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdoutBytes": len(result.stdout),
        "stderrSha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderrBytes": len(result.stderr),
    }


def _safe_absolute_path(value: Any, field: str) -> Path:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProofPlaneError("%s must be one bounded absolute path" % field)
    path = Path(value)
    if any(part in ("", ".", "..") for part in path.parts[1:]):
        raise ProofPlaneError("%s must be lexically normalized" % field)
    return path


def _stat_shape(value: os.stat_result) -> Tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
    )


def _secure_authority_mode(value: os.stat_result, field: str) -> None:
    if value.st_uid not in (0, os.getuid()) or stat.S_IMODE(value.st_mode) & 0o022:
        raise ProofPlaneError("%s must not be group/world writable or foreign-owned" % field)


def _closed_directory(path: Path, field: str) -> None:
    """Reject a directory reached through any symlink or non-directory."""

    if not path.is_absolute():
        raise ProofPlaneError("%s must be absolute" % field)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            evidence = current.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s is missing" % field) from exc
        if stat.S_ISLNK(evidence.st_mode) or not stat.S_ISDIR(evidence.st_mode):
            raise ProofPlaneError("%s must have no symlink directory components" % field)
        _secure_authority_mode(evidence, field)


def _resolve_macos_root(path: Path, field: str) -> Path:
    """Resolve only macOS's fixed /var -> /private/var compatibility alias."""

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if path != resolved:
        parts = path.parts
        expected = Path("/private/var", *parts[2:]) if len(parts) >= 2 and parts[1] == "var" else None
        if expected is None or resolved != expected:
            raise ProofPlaneError("%s must not traverse a symlink" % field)
    _closed_directory(resolved, field)
    return resolved


def _secure_regular_path(path: Path, field: str, *, allow_empty: bool = False) -> os.stat_result:
    try:
        evidence = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if (
        stat.S_ISLNK(evidence.st_mode)
        or not stat.S_ISREG(evidence.st_mode)
        or evidence.st_nlink != 1
        or evidence.st_size > _MAX_RUNTIME_FILE_BYTES
        or (not allow_empty and evidence.st_size < 1)
    ):
        raise ProofPlaneError("%s must be one secure regular file" % field)
    _secure_authority_mode(evidence, field)
    return evidence


def _file_evidence(path: Path, field: str, *, executable: bool = False) -> Dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_RUNTIME_FILE_BYTES
            or (executable and not (before.st_mode & 0o111))
        ):
            raise ProofPlaneError("%s must be one bounded regular file" % field)
        _secure_authority_mode(before, field)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RUNTIME_FILE_BYTES:
                raise ProofPlaneError("%s exceeds the closed file limit" % field)
            digest.update(chunk)
        after = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s changed during inspection" % field) from exc
        if (
            total != before.st_size
            or _stat_shape(before) != _stat_shape(after)
            or stat.S_ISLNK(current.st_mode)
            or _stat_shape(current) != _stat_shape(after)
        ):
            raise ProofPlaneError("%s changed during inspection" % field)
    finally:
        os.close(descriptor)
    return {
        "sha256": digest.hexdigest(),
        "bytes": before.st_size,
        "mode": stat.S_IMODE(before.st_mode),
    }


def _closed_plugin_tree(install_root: Path) -> None:
    root = install_root / _PLUGIN_ROOT
    _closed_directory(root, "Apple built-in plugin directory")
    directories = {_PLUGIN_ROOT}
    files = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise ProofPlaneError("Apple built-in plugin tree is unreadable") from exc
        for entry in entries:
            relative = Path(entry.path).relative_to(install_root).as_posix()
            try:
                evidence = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ProofPlaneError("Apple built-in plugin tree changed") from exc
            if stat.S_ISLNK(evidence.st_mode):
                raise ProofPlaneError("Apple built-in plugin tree must contain no symlinks")
            if stat.S_ISDIR(evidence.st_mode):
                directories.add(relative)
                pending.append(Path(entry.path))
            elif stat.S_ISREG(evidence.st_mode):
                files.add(relative)
            else:
                raise ProofPlaneError("Apple built-in plugin tree contains a special file")
    expected_files = {
        relative for relative in _INSTALLED_FILES if relative.startswith(_PLUGIN_ROOT + "/")
    }
    if directories != set(_PLUGIN_DIRECTORIES) or files != expected_files:
        raise ProofPlaneError("Apple built-in plugin tree differs from the 1.2.2 inventory")


def _signature(path: Path, expected_identifier: str) -> Dict[str, str]:
    verify = _run_command(
        (str(_CODESIGN), "--verify", "--strict", "--verbose=2", str(path)),
        timeout_seconds=30,
        maximum_output_bytes=100_000,
    )
    if verify.returncode != 0:
        raise ProofPlaneError("Apple runtime component code signature did not verify")
    details = _run_command(
        (str(_CODESIGN), "-dv", "--verbose=4", str(path)),
        timeout_seconds=30,
        maximum_output_bytes=100_000,
    )
    if details.returncode != 0:
        raise ProofPlaneError("Apple runtime component signature identity is unavailable")
    try:
        lines = (details.stdout + details.stderr).decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise ProofPlaneError("Apple runtime component signature is not UTF-8") from exc
    identifiers = [line.split("=", 1)[1] for line in lines if line.startswith("Identifier=")]
    teams = [line.split("=", 1)[1] for line in lines if line.startswith("TeamIdentifier=")]
    authorities = [line.split("=", 1)[1] for line in lines if line.startswith("Authority=")]
    cdhashes = [line.split("=", 1)[1] for line in lines if line.startswith("CDHash=")]
    if identifiers != [expected_identifier] or teams != [_TEAM_ID]:
        raise ProofPlaneError("Apple runtime component has an unexpected signing identity")
    if not authorities or authorities[0] != _AUTHORITY:
        raise ProofPlaneError("Apple runtime component lacks Apple's Developer ID authority")
    if len(cdhashes) != 1 or _CDHASH.fullmatch(cdhashes[0]) is None:
        raise ProofPlaneError("Apple runtime component lacks one SHA-256 CDHash")
    return {
        "identifier": expected_identifier,
        "teamIdentifier": _TEAM_ID,
        "authority": _AUTHORITY,
        "cdHash": cdhashes[0],
    }


def _version_components(raw: bytes) -> Tuple[str, Tuple[Dict[str, str], ...]]:
    value = _json(raw, "Apple container system version")
    if not isinstance(value, list) or len(value) != 2:
        raise ProofPlaneError("Apple container system version must report CLI and API server")
    components = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple container version component is invalid")
        exact_fields(item, ("version", "buildType", "commit", "appName"), "Apple container version component")
        normalized: Dict[str, str] = {}
        for name in ("version", "buildType", "commit", "appName"):
            text = item[name]
            if (
                not isinstance(text, str)
                or not text
                or text != text.strip()
                or len(text) > 512
                or any(ord(character) < 32 or ord(character) == 127 for character in text)
            ):
                raise ProofPlaneError("Apple container version component field is invalid")
            normalized[name] = text
        if normalized["buildType"] != "release":
            raise ProofPlaneError("Apple container runtime must use a release build")
        components.append(normalized)
    if [item["appName"] for item in components] != ["container", "container-apiserver"]:
        raise ProofPlaneError("Apple container version components are incomplete or reordered")
    cli_version = components[0]["version"]
    if _SEMVER.fullmatch(cli_version) is None or cli_version != APPLE_RUNTIME_VERSION:
        raise ProofPlaneError("Apple container CLI version must be exactly 1.2.2")
    if components[0]["commit"] != components[1]["commit"]:
        raise ProofPlaneError("Apple container CLI and API server commits differ")
    if re.search(r"(?:^|\s)" + re.escape(cli_version) + r"(?:\s|$|\()", components[1]["version"]) is None:
        raise ProofPlaneError("Apple container API server does not report the CLI release")
    return cli_version, tuple(components)


def _status(raw: bytes, components: Sequence[Mapping[str, str]]) -> Tuple[Path, Path, Dict[str, Any]]:
    value = _json(raw, "Apple container system status")
    if not isinstance(value, Mapping):
        raise ProofPlaneError("Apple container system status must be an object")
    exact_fields(
        value,
        (
            "status", "appRoot", "installRoot", "logRoot", "apiServerVersion",
            "apiServerCommit", "apiServerBuild", "apiServerAppName",
        ),
        "Apple container system status",
    )
    if value["status"] != "running":
        raise ProofPlaneError("Apple container API server must already be running")
    app_root = _resolve_macos_root(
        _safe_absolute_path(value["appRoot"], "Apple container appRoot"),
        "Apple container appRoot",
    )
    install_root = _resolve_macos_root(
        _safe_absolute_path(value["installRoot"], "Apple container installRoot"),
        "Apple container installRoot",
    )
    if (
        value["apiServerAppName"] != "container-apiserver"
        or value["apiServerBuild"] != "release"
        or value["apiServerCommit"] != components[1]["commit"]
        or value["apiServerVersion"] != components[1]["version"]
    ):
        raise ProofPlaneError("Apple container status differs from the live version response")
    log_root = value["logRoot"]
    if log_root is not None:
        _safe_absolute_path(log_root, "Apple container logRoot")
    normalized_status = dict(value)
    normalized_status["appRoot"] = str(app_root)
    normalized_status["installRoot"] = str(install_root)
    return app_root, install_root, normalized_status


def _property_config(raw: bytes) -> Dict[str, Any]:
    value = _json(raw, "Apple container effective properties")
    if not isinstance(value, Mapping):
        raise ProofPlaneError("Apple container effective properties must be an object")
    exact_fields(
        value,
        ("build", "container", "dns", "kernel", "machine", "network", "registry", "vminit"),
        "Apple container effective properties",
    )
    kernel = value["kernel"]
    vminit = value["vminit"]
    if not isinstance(kernel, Mapping) or not isinstance(vminit, Mapping):
        raise ProofPlaneError("Apple container kernel and vminit properties must be objects")
    exact_fields(kernel, ("binaryPath", "url", "digest"), "Apple container kernel properties")
    exact_fields(vminit, ("image",), "Apple container vminit properties")
    digest = kernel["digest"]
    if not isinstance(digest, str) or not digest.startswith("sha256:") or _SHA256.fullmatch(digest[7:]) is None:
        raise ProofPlaneError("Apple container kernel archive digest is invalid")
    if not isinstance(kernel["url"], str) or not kernel["url"].startswith("https://"):
        raise ProofPlaneError("Apple container kernel URL must use HTTPS")
    if not isinstance(kernel["binaryPath"], str) or not kernel["binaryPath"] or len(kernel["binaryPath"]) > 1000:
        raise ProofPlaneError("Apple container kernel binaryPath is invalid")
    reference = vminit["image"]
    if not isinstance(reference, str) or _REFERENCE.fullmatch(reference) is None or "@" in reference:
        raise ProofPlaneError("Apple container vminit image must be one configured tag")
    return dict(value)


def _immutable_reference(reference: str, digest: str) -> str:
    slash = reference.rfind("/")
    colon = reference.rfind(":")
    repository = reference[:colon] if colon > slash else reference
    if not repository or repository.endswith("/"):
        raise ProofPlaneError("Apple container vminit reference has no repository")
    return "%s@sha256:%s" % (repository, digest)


def _descriptor(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an OCI descriptor" % field)
    required = {"mediaType", "digest", "size"}
    allowed = required | {"urls", "annotations", "platform", "artifactType"}
    if not required.issubset(value) or not set(value).issubset(allowed):
        raise ProofPlaneError("%s has an invalid OCI descriptor shape" % field)
    media_type, digest, size = value["mediaType"], value["digest"], value["size"]
    if not isinstance(media_type, str) or _MEDIA_TYPE.fullmatch(media_type) is None:
        raise ProofPlaneError("%s mediaType is invalid" % field)
    if not isinstance(digest, str) or not digest.startswith("sha256:") or _SHA256.fullmatch(digest[7:]) is None:
        raise ProofPlaneError("%s digest is invalid" % field)
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= _MAX_OCI_BLOB_BYTES:
        raise ProofPlaneError("%s size is invalid" % field)
    urls = value.get("urls")
    if urls is not None and (
        not isinstance(urls, list)
        or len(urls) > 32
        or any(
            not isinstance(item, str)
            or not item.startswith("https://")
            or len(item) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in urls
        )
    ):
        raise ProofPlaneError("%s URLs are invalid" % field)
    annotations = value.get("annotations")
    if annotations is not None and (
        not isinstance(annotations, Mapping)
        or len(annotations) > 128
        or any(
            not isinstance(key, str)
            or not key
            or len(key) > 512
            or not isinstance(item, str)
            or len(item) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in key + item)
            for key, item in annotations.items()
        )
    ):
        raise ProofPlaneError("%s annotations are invalid" % field)
    platform_value = value.get("platform")
    if platform_value is not None:
        if not isinstance(platform_value, Mapping) or not {"os", "architecture"}.issubset(platform_value):
            raise ProofPlaneError("%s platform is invalid" % field)
        if not set(platform_value).issubset({"os", "architecture", "variant", "os.version", "os.features"}):
            raise ProofPlaneError("%s platform has unknown fields" % field)
        for name in ("os", "architecture", "variant", "os.version"):
            item = platform_value.get(name)
            if item is not None and (
                not isinstance(item, str)
                or not item
                or len(item) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in item)
            ):
                raise ProofPlaneError("%s platform.%s is invalid" % (field, name))
        features = platform_value.get("os.features")
        if features is not None and (
            not isinstance(features, list)
            or len(features) > 64
            or any(not isinstance(item, str) or not item or len(item) > 256 for item in features)
        ):
            raise ProofPlaneError("%s platform os.features is invalid" % field)
    artifact_type = value.get("artifactType")
    if artifact_type is not None and (
        not isinstance(artifact_type, str) or _MEDIA_TYPE.fullmatch(artifact_type) is None
    ):
        raise ProofPlaneError("%s artifactType is invalid" % field)
    return dict(value)


def _blob(
    app_root: Path,
    descriptor: Mapping[str, Any],
    field: str,
    *,
    retain: bool,
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    normalized = _descriptor(descriptor, field)
    digest = normalized["digest"][7:]
    path = app_root / "content" / "blobs" / "sha256" / digest
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor_fd = os.open(str(path), flags)
    except OSError as exc:
        raise ProofPlaneError("%s local OCI blob is unavailable" % field) from exc
    try:
        before = os.fstat(descriptor_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != normalized["size"]
        ):
            raise ProofPlaneError("%s local OCI blob differs from its descriptor" % field)
        _secure_authority_mode(before, field)
        if retain and before.st_size > _MAX_CONFIG_BYTES:
            raise ProofPlaneError("%s JSON blob exceeds the closed limit" % field)
        hasher = hashlib.sha256()
        chunks = [] if retain else None
        total = 0
        while True:
            chunk = os.read(descriptor_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_OCI_BLOB_BYTES:
                raise ProofPlaneError("%s local OCI blob exceeds the closed limit" % field)
            hasher.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(descriptor_fd)
        try:
            current = path.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s local OCI blob changed during inspection" % field) from exc
        shape = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            getattr(item, "st_mtime_ns", int(item.st_mtime * 1_000_000_000)),
        )
        if (
            total != normalized["size"]
            or hasher.hexdigest() != digest
            or shape(before) != shape(after)
            or stat.S_ISLNK(current.st_mode)
            or not os.path.samestat(current, after)
        ):
            raise ProofPlaneError("%s local OCI blob differs from its descriptor" % field)
    finally:
        os.close(descriptor_fd)
    return (b"".join(chunks) if chunks is not None else None), {
        "digest": digest,
        "bytes": normalized["size"],
        "mediaType": normalized["mediaType"],
    }


def _init_image(app_root: Path, configured_reference: str) -> Dict[str, Any]:
    state_path = app_root / "state.json"
    _secure_regular_path(state_path, "Apple image state")
    _closed_directory(app_root / "content/blobs/sha256", "Apple OCI content directory")
    state_raw = read_bounded_regular_bytes(state_path, maximum_bytes=_MAX_STATE_BYTES, field="Apple image state")
    state = _json(state_raw, "Apple image state", _MAX_STATE_BYTES)
    if not isinstance(state, Mapping) or not 1 <= len(state) <= 10_000:
        raise ProofPlaneError("Apple image state must be one bounded reference map")
    configured = _descriptor(state.get(configured_reference), "configured vminit image")
    if configured["mediaType"] not in _INDEX_MEDIA_TYPES:
        raise ProofPlaneError("Apple vminit reference must bind an OCI image index")
    index_digest = configured["digest"][7:]
    immutable = _immutable_reference(configured_reference, index_digest)
    alias = _descriptor(state.get(immutable), "immutable vminit image alias")
    if canonical_digest(alias) != canonical_digest(configured):
        raise ProofPlaneError("Apple vminit tag and immutable alias bind different descriptors")
    for reference, value in state.items():
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in reference)
        ):
            raise ProofPlaneError("Apple image state contains an invalid reference")
        candidate = _descriptor(value, "Apple image state descriptor")
        annotations = candidate.get("annotations", {})
        if annotations.get("com.apple.containerization.image.name") == immutable:
            raise ProofPlaneError("Apple vminit immutable alias can be shadowed by an annotation")

    blobs: Dict[str, Dict[str, Any]] = {}
    total_bytes = 0

    def add_blob(
        descriptor: Mapping[str, Any], field: str, *, retain: bool = False
    ) -> Optional[bytes]:
        nonlocal total_bytes
        normalized = _descriptor(descriptor, field)
        digest = normalized["digest"][7:]
        existing = blobs.get(digest)
        if existing is not None:
            if (
                existing["bytes"] != normalized["size"]
                or existing["mediaType"] != normalized["mediaType"]
            ):
                raise ProofPlaneError("Apple vminit OCI closure contains a conflicting digest")
            if retain:
                raw, _evidence = _blob(app_root, normalized, field, retain=True)
                return raw
            return None
        raw, evidence = _blob(app_root, descriptor, field, retain=retain)
        blobs[digest] = evidence
        total_bytes += evidence["bytes"]
        if len(blobs) > _MAX_OCI_BLOBS or total_bytes > _MAX_OCI_TOTAL_BYTES:
            raise ProofPlaneError("Apple vminit OCI closure exceeds the closed limit")
        return raw

    index_raw = add_blob(configured, "vminit OCI index", retain=True)
    assert index_raw is not None
    index = _json(index_raw, "vminit OCI index", _MAX_CONFIG_BYTES)
    if not isinstance(index, Mapping) or index.get("schemaVersion") != 2:
        raise ProofPlaneError("Apple vminit OCI index is invalid")
    manifests = index.get("manifests") if isinstance(index, Mapping) else None
    if not isinstance(manifests, list) or not 1 <= len(manifests) <= 32:
        raise ProofPlaneError("Apple vminit OCI index has an invalid manifest set")
    runnable = []
    for position, item in enumerate(manifests):
        desc = _descriptor(item, "vminit manifest descriptor")
        platform_value = desc.get("platform")
        if (
            isinstance(platform_value, Mapping)
            and platform_value.get("os") == "linux"
            and platform_value.get("architecture") == "arm64"
        ):
            if desc["mediaType"] not in _MANIFEST_MEDIA_TYPES:
                raise ProofPlaneError("Apple vminit runnable descriptor is not an image manifest")
            runnable.append(desc)
        raw = add_blob(desc, "vminit manifest %d" % position, retain=True)
        assert raw is not None
        manifest = _json(raw, "vminit manifest %d" % position, _MAX_CONFIG_BYTES)
        if desc["mediaType"] in _MANIFEST_MEDIA_TYPES:
            if not isinstance(manifest, Mapping) or manifest.get("schemaVersion") != 2:
                raise ProofPlaneError("Apple vminit manifest is invalid")
            config = manifest.get("config")
            layers = manifest.get("layers")
            if not isinstance(layers, list) or len(layers) > 256:
                raise ProofPlaneError("Apple vminit manifest layer set is invalid")
            add_blob(config, "vminit configuration %d" % position)
            for layer_position, layer in enumerate(layers):
                add_blob(layer, "vminit layer %d.%d" % (position, layer_position))
    if len(runnable) != 1:
        raise ProofPlaneError("Apple vminit image must have exactly one linux/arm64 manifest")
    closure = [blobs[name] for name in sorted(blobs)]
    return {
        "configuredReference": configured_reference,
        "immutableReference": immutable,
        "indexDigest": index_digest,
        "descriptorSha256": canonical_digest(configured),
        "stateFileSha256": hashlib.sha256(state_raw).hexdigest(),
        "blobs": closure,
        "blobCount": len(closure),
        "totalBlobBytes": sum(item["bytes"] for item in closure),
        "closureSha256": canonical_digest(closure),
        "annotationShadowingAbsent": True,
    }


def _kernel(app_root: Path, configured: Mapping[str, Any]) -> Dict[str, Any]:
    alias = app_root / "kernels" / "default.kernel-arm64"
    _closed_directory(alias.parent, "Apple managed kernel directory")
    try:
        alias_stat = alias.lstat()
    except OSError as exc:
        raise ProofPlaneError("Apple default arm64 kernel alias is absent") from exc
    if not stat.S_ISLNK(alias_stat.st_mode):
        raise ProofPlaneError("Apple default arm64 kernel must use its managed symlink")
    if alias_stat.st_uid not in (0, os.getuid()):
        raise ProofPlaneError("Apple default arm64 kernel alias is foreign-owned")
    try:
        target = alias.resolve(strict=True)
        target.relative_to((app_root / "kernels").resolve())
    except (OSError, ValueError) as exc:
        raise ProofPlaneError("Apple default arm64 kernel escapes its managed directory") from exc
    evidence = _file_evidence(target, "Apple default arm64 kernel")
    if alias.resolve(strict=True) != target:
        raise ProofPlaneError("Apple default arm64 kernel alias changed during inspection")
    return {
        "aliasPath": str(alias),
        "resolvedPath": str(target),
        "sha256": evidence["sha256"],
        "bytes": evidence["bytes"],
        "configuredArchiveDigest": configured["digest"][7:],
        "configuredArchiveUrl": configured["url"],
        "configuredBinaryPath": configured["binaryPath"],
    }


def _config_layer(path: Path) -> Dict[str, Any]:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "present": False, "sha256": None}
    except OSError as exc:
        raise ProofPlaneError("Apple container configuration layer is unavailable") from exc
    if stat.S_ISLNK(current.st_mode):
        raise ProofPlaneError("Apple container configuration layer must not be a symlink")
    _secure_regular_path(path, "Apple container configuration layer", allow_empty=True)
    _closed_directory(path.parent, "Apple container configuration directory")
    raw = read_bounded_regular_bytes(path, maximum_bytes=_MAX_CONFIG_BYTES, field="Apple container configuration layer")
    return {"path": str(path), "present": True, "sha256": hashlib.sha256(raw).hexdigest()}


def _service_definition(path: Path, expected: Mapping[str, Any]) -> Dict[str, Any]:
    _closed_directory(path.parent, "Apple launchd service state directory")
    _secure_regular_path(path, "Apple launchd service definition")
    raw = read_bounded_regular_bytes(path, maximum_bytes=_MAX_CONFIG_BYTES, field="Apple launchd service definition")
    try:
        value = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ProofPlaneError("Apple launchd service definition is invalid") from exc
    if not isinstance(value, Mapping):
        raise ProofPlaneError("Apple launchd service definition must be an object")
    environment = value.get("EnvironmentVariables")
    if not isinstance(environment, Mapping) or any(
        isinstance(name, str) and name.upper().startswith("DYLD_") for name in environment
    ):
        raise ProofPlaneError("Apple launchd service definition has an unsafe environment")
    if dict(value) != dict(expected):
        raise ProofPlaneError("Apple launchd service definition differs from the safe 1.2.2 policy")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "semanticSha256": canonical_digest(value),
    }


def _expected_service(
    *,
    label: str,
    arguments: Sequence[str],
    app_root: Path,
    install_root: Path,
    log_root: Optional[str],
    run_at_load: bool,
    mach_service: str,
) -> Dict[str, Any]:
    environment = {
        "CONTAINER_APP_ROOT": str(app_root),
        "CONTAINER_INSTALL_ROOT": str(install_root),
    }
    if log_root is not None:
        environment["CONTAINER_LOG_ROOT"] = log_root
    return {
        "Label": label,
        "ProgramArguments": list(arguments),
        "EnvironmentVariables": environment,
        "LimitLoadToSessionType": ["Aqua", "Background", "System"],
        "RunAtLoad": run_at_load,
        "MachServices": {mach_service: True},
    }


def _installed_file_inventory(install_root: Path) -> Tuple[Dict[str, Any], ...]:
    installed = []
    for relative, identifier in sorted(_INSTALLED_FILES.items()):
        path = install_root / relative
        evidence = _file_evidence(
            path,
            "Apple installed runtime file %s" % relative,
            executable=identifier is not None,
        )
        item: Dict[str, Any] = {"relativePath": relative, **evidence}
        if identifier is not None:
            item["codeSignature"] = _signature(path, identifier)
            if _file_evidence(
                path,
                "Apple signed runtime file %s" % relative,
                executable=True,
            ) != evidence:
                raise ProofPlaneError("Apple runtime component changed during codesign inspection")
        installed.append(item)
    return tuple(installed)


def _service_definition_inventory(
    app_root: Path, install_root: Path, status: Mapping[str, Any]
) -> Tuple[Dict[str, Any], ...]:
    return (
        _service_definition(
            app_root / "apiserver" / "apiserver.plist",
            _expected_service(
                label="com.apple.container.apiserver",
                arguments=(str(install_root / "bin" / "container-apiserver"), "start"),
                app_root=app_root,
                install_root=install_root,
                log_root=status["logRoot"],
                run_at_load=True,
                mach_service="com.apple.container.apiserver",
            ),
        ),
        _service_definition(
            app_root / "plugin-state" / "container-core-images" / "service.plist",
            _expected_service(
                label="com.apple.container.container-core-images",
                arguments=(
                    str(
                        install_root
                        / "libexec/container/plugins/container-core-images/bin/container-core-images"
                    ),
                    "start",
                ),
                app_root=app_root,
                install_root=install_root,
                log_root=status["logRoot"],
                run_at_load=False,
                mach_service="com.apple.container.core.container-core-images",
            ),
        ),
        _service_definition(
            app_root / "plugin-state" / "machine-apiserver" / "service.plist",
            _expected_service(
                label="com.apple.container.machine-apiserver",
                arguments=(
                    str(
                        install_root
                        / "libexec/container/plugins/machine-apiserver/bin/machine-apiserver"
                    ),
                    "start",
                    "--resources",
                    str(
                        install_root
                        / "libexec/container/plugins/machine-apiserver/resources"
                    ),
                ),
                app_root=app_root,
                install_root=install_root,
                log_root=status["logRoot"],
                run_at_load=False,
                mach_service="com.apple.container.core.machine-apiserver",
            ),
        ),
    )


def _config_layer_inventory(
    app_root: Path, install_root: Path
) -> Tuple[Dict[str, Any], ...]:
    return (
        _config_layer(app_root / "config" / "config.toml"),
        _config_layer(install_root / "etc" / "container" / "config.toml"),
    )


def _self_digest(document: Mapping[str, Any]) -> Dict[str, Any]:
    if "tcbSha256" in document:
        raise ProofPlaneError("Apple runtime TCB body must omit its self-digest")
    return {**document, "tcbSha256": canonical_digest(document)}


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProofPlaneError("%s must be one lowercase SHA-256 digest" % field)
    return value


def _require_count(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProofPlaneError("%s is outside its closed integer range" % field)
    return value


def _validate_capture(value: Any, field: str) -> None:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(
        value,
        ("returnCode", "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes"),
        field,
    )
    if value["returnCode"] != 0:
        raise ProofPlaneError("%s did not succeed" % field)
    _require_sha256(value["stdoutSha256"], field + ".stdoutSha256")
    _require_sha256(value["stderrSha256"], field + ".stderrSha256")
    _require_count(value["stdoutBytes"], field + ".stdoutBytes", _MAX_COMMAND_OUTPUT)
    if _require_count(value["stderrBytes"], field + ".stderrBytes", _MAX_COMMAND_OUTPUT) != 0:
        raise ProofPlaneError("%s must have empty stderr" % field)
    if value["stderrSha256"] != hashlib.sha256(b"").hexdigest():
        raise ProofPlaneError("%s empty stderr digest is invalid" % field)


def validate_apple_container_tcb_document(value: Any) -> Dict[str, Any]:
    """Validate and normalize one closed ``apple-container`` TCB document.

    This validates document structure and all internal bindings.  It does not
    re-inspect the host; callers use :func:`inspect_apple_container_tcb` before
    and after a run for that purpose.
    """

    if not isinstance(value, Mapping):
        raise ProofPlaneError("Apple runtime TCB document must be an object")
    fields = (
        "schemaVersion", "contractVersion", "platform", "assuranceScope",
        "runtime", "versionQuery", "statusQuery", "propertyQuery", "hostFiles",
        "hostFilesSha256", "serviceDefinitions", "serviceDefinitionsSha256",
        "configLayers", "configLayersSha256", "kernel", "initImage",
        "userPluginOverrideDirectoryAbsent", "tcbSha256",
    )
    exact_fields(value, fields, "Apple runtime TCB document")
    if (
        value["schemaVersion"] != APPLE_RUNTIME_TCB_SCHEMA
        or value["contractVersion"] != APPLE_RUNTIME_TCB_CONTRACT
        or value["platform"] != "macos/arm64"
        or value["assuranceScope"] != _ASSURANCE_SCOPE
        or value["userPluginOverrideDirectoryAbsent"] is not True
    ):
        raise ProofPlaneError("Apple runtime TCB contract identity is invalid")

    runtime = value["runtime"]
    if not isinstance(runtime, Mapping):
        raise ProofPlaneError("Apple runtime TCB runtime must be an object")
    exact_fields(runtime, ("name", "version", "binarySha256"), "Apple runtime TCB runtime")
    if runtime["name"] != "apple-container" or runtime["version"] != APPLE_RUNTIME_VERSION:
        raise ProofPlaneError("Apple runtime TCB must bind Apple container 1.2.2")
    _require_sha256(runtime["binarySha256"], "Apple runtime binarySha256")

    version_query = value["versionQuery"]
    if not isinstance(version_query, Mapping):
        raise ProofPlaneError("Apple runtime versionQuery must be an object")
    exact_fields(version_query, ("commandSha256", "process", "components"), "Apple runtime versionQuery")
    _require_sha256(version_query["commandSha256"], "Apple runtime version command")
    _validate_capture(version_query["process"], "Apple runtime version process")
    runtime_version, components = _version_components(canonical_bytes(version_query["components"]))
    if runtime_version != runtime["version"]:
        raise ProofPlaneError("Apple runtime component version differs from runtime identity")

    status_query = value["statusQuery"]
    if not isinstance(status_query, Mapping):
        raise ProofPlaneError("Apple runtime statusQuery must be an object")
    exact_fields(status_query, ("commandSha256", "process", "status"), "Apple runtime statusQuery")
    _require_sha256(status_query["commandSha256"], "Apple runtime status command")
    _validate_capture(status_query["process"], "Apple runtime status process")
    status_value = status_query["status"]
    if not isinstance(status_value, Mapping):
        raise ProofPlaneError("Apple runtime status must be an object")
    exact_fields(
        status_value,
        (
            "status", "appRoot", "installRoot", "logRoot", "apiServerVersion",
            "apiServerCommit", "apiServerBuild", "apiServerAppName",
        ),
        "Apple runtime status",
    )
    app_root = _safe_absolute_path(status_value["appRoot"], "Apple runtime status appRoot")
    install_root = _safe_absolute_path(status_value["installRoot"], "Apple runtime status installRoot")
    if status_value["logRoot"] is not None:
        _safe_absolute_path(status_value["logRoot"], "Apple runtime status logRoot")
    if (
        status_value["status"] != "running"
        or status_value["apiServerVersion"] != components[1]["version"]
        or status_value["apiServerCommit"] != components[1]["commit"]
        or status_value["apiServerBuild"] != "release"
        or status_value["apiServerAppName"] != "container-apiserver"
    ):
        raise ProofPlaneError("Apple runtime status does not bind the version components")
    runtime_path = install_root / "bin" / "container"
    commands = (
        (version_query, (str(runtime_path), "system", "version", "--format", "json")),
        (status_query, (str(runtime_path), "system", "status", "--format", "json")),
    )
    for query, argv in commands:
        if query["commandSha256"] != canonical_digest(list(argv)):
            raise ProofPlaneError("Apple runtime query command binding is invalid")

    property_query = value["propertyQuery"]
    if not isinstance(property_query, Mapping):
        raise ProofPlaneError("Apple runtime propertyQuery must be an object")
    exact_fields(
        property_query,
        ("commandSha256", "process", "effectiveConfig", "effectiveConfigSha256"),
        "Apple runtime propertyQuery",
    )
    _validate_capture(property_query["process"], "Apple runtime property process")
    effective = _property_config(canonical_bytes(property_query["effectiveConfig"]))
    if property_query["effectiveConfigSha256"] != canonical_digest(effective):
        raise ProofPlaneError("Apple runtime effective configuration digest is invalid")
    property_argv = (str(runtime_path), "system", "property", "list", "--format", "json")
    if property_query["commandSha256"] != canonical_digest(list(property_argv)):
        raise ProofPlaneError("Apple runtime property command binding is invalid")

    host_files = value["hostFiles"]
    if not isinstance(host_files, list) or len(host_files) != len(_INSTALLED_FILES):
        raise ProofPlaneError("Apple runtime hostFiles must contain the complete 1.2.2 inventory")
    for item, (relative, identifier) in zip(host_files, sorted(_INSTALLED_FILES.items())):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple runtime hostFiles entry must be an object")
        expected_fields = ("relativePath", "sha256", "bytes", "mode") + (
            ("codeSignature",) if identifier is not None else ()
        )
        exact_fields(item, expected_fields, "Apple runtime hostFiles entry")
        if item["relativePath"] != relative:
            raise ProofPlaneError("Apple runtime hostFiles inventory is reordered or incomplete")
        _require_sha256(item["sha256"], "Apple runtime host file digest")
        if not 1 <= _require_count(item["bytes"], "Apple runtime host file bytes", _MAX_RUNTIME_FILE_BYTES):
            raise ProofPlaneError("Apple runtime host file must not be empty")
        if not 0 <= _require_count(item["mode"], "Apple runtime host file mode", 0o7777) <= 0o7777:
            raise ProofPlaneError("Apple runtime host file mode is invalid")
        if identifier is not None:
            signature = item["codeSignature"]
            if not isinstance(signature, Mapping):
                raise ProofPlaneError("Apple runtime codeSignature must be an object")
            exact_fields(
                signature,
                ("identifier", "teamIdentifier", "authority", "cdHash"),
                "Apple runtime codeSignature",
            )
            if (
                signature["identifier"] != identifier
                or signature["teamIdentifier"] != _TEAM_ID
                or signature["authority"] != _AUTHORITY
                or not isinstance(signature["cdHash"], str)
                or _CDHASH.fullmatch(signature["cdHash"]) is None
            ):
                raise ProofPlaneError("Apple runtime codeSignature identity is invalid")
    if host_files[0]["sha256"] != runtime["binarySha256"]:
        raise ProofPlaneError("Apple runtime binary digest differs from hostFiles")
    if value["hostFilesSha256"] != canonical_digest(host_files):
        raise ProofPlaneError("Apple runtime hostFiles digest is invalid")

    service_definitions = value["serviceDefinitions"]
    service_paths = (
        app_root / "apiserver/apiserver.plist",
        app_root / "plugin-state/container-core-images/service.plist",
        app_root / "plugin-state/machine-apiserver/service.plist",
    )
    if not isinstance(service_definitions, list) or len(service_definitions) != len(service_paths):
        raise ProofPlaneError("Apple runtime serviceDefinitions are incomplete")
    for item, path in zip(service_definitions, service_paths):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple runtime service definition evidence must be an object")
        exact_fields(item, ("path", "sha256", "semanticSha256"), "Apple runtime service definition evidence")
        if item["path"] != str(path):
            raise ProofPlaneError("Apple runtime service definition path is invalid")
        _require_sha256(item["sha256"], "Apple runtime service definition digest")
        _require_sha256(item["semanticSha256"], "Apple runtime service semantic digest")
    expected_services = (
        _expected_service(
            label="com.apple.container.apiserver",
            arguments=(str(install_root / "bin/container-apiserver"), "start"),
            app_root=app_root,
            install_root=install_root,
            log_root=status_value["logRoot"],
            run_at_load=True,
            mach_service="com.apple.container.apiserver",
        ),
        _expected_service(
            label="com.apple.container.container-core-images",
            arguments=(
                str(install_root / "libexec/container/plugins/container-core-images/bin/container-core-images"),
                "start",
            ),
            app_root=app_root,
            install_root=install_root,
            log_root=status_value["logRoot"],
            run_at_load=False,
            mach_service="com.apple.container.core.container-core-images",
        ),
        _expected_service(
            label="com.apple.container.machine-apiserver",
            arguments=(
                str(install_root / "libexec/container/plugins/machine-apiserver/bin/machine-apiserver"),
                "start", "--resources",
                str(install_root / "libexec/container/plugins/machine-apiserver/resources"),
            ),
            app_root=app_root,
            install_root=install_root,
            log_root=status_value["logRoot"],
            run_at_load=False,
            mach_service="com.apple.container.core.machine-apiserver",
        ),
    )
    if [item["semanticSha256"] for item in service_definitions] != [
        canonical_digest(item) for item in expected_services
    ]:
        raise ProofPlaneError("Apple runtime service semantic bindings are invalid")
    if value["serviceDefinitionsSha256"] != canonical_digest(service_definitions):
        raise ProofPlaneError("Apple runtime serviceDefinitions digest is invalid")

    config_layers = value["configLayers"]
    layer_paths = (
        app_root / "config/config.toml",
        install_root / "etc/container/config.toml",
    )
    if not isinstance(config_layers, list) or len(config_layers) != 2:
        raise ProofPlaneError("Apple runtime configLayers are incomplete")
    for item, path in zip(config_layers, layer_paths):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple runtime config layer must be an object")
        exact_fields(item, ("path", "present", "sha256"), "Apple runtime config layer")
        if item["path"] != str(path) or not isinstance(item["present"], bool):
            raise ProofPlaneError("Apple runtime config layer binding is invalid")
        if item["present"]:
            _require_sha256(item["sha256"], "Apple runtime config layer digest")
        elif item["sha256"] is not None:
            raise ProofPlaneError("Absent Apple runtime config layer must have a null digest")
    if value["configLayersSha256"] != canonical_digest(config_layers):
        raise ProofPlaneError("Apple runtime configLayers digest is invalid")

    kernel = value["kernel"]
    if not isinstance(kernel, Mapping):
        raise ProofPlaneError("Apple runtime kernel must be an object")
    exact_fields(
        kernel,
        (
            "aliasPath", "resolvedPath", "sha256", "bytes", "configuredArchiveDigest",
            "configuredArchiveUrl", "configuredBinaryPath",
        ),
        "Apple runtime kernel",
    )
    if kernel["aliasPath"] != str(app_root / "kernels/default.kernel-arm64"):
        raise ProofPlaneError("Apple runtime kernel alias path is invalid")
    resolved_kernel = _safe_absolute_path(kernel["resolvedPath"], "Apple runtime resolved kernel")
    try:
        resolved_kernel.relative_to(app_root / "kernels")
    except ValueError as exc:
        raise ProofPlaneError("Apple runtime resolved kernel escapes appRoot") from exc
    _require_sha256(kernel["sha256"], "Apple runtime kernel digest")
    if not 1 <= _require_count(kernel["bytes"], "Apple runtime kernel bytes", _MAX_RUNTIME_FILE_BYTES):
        raise ProofPlaneError("Apple runtime kernel must not be empty")
    configured_kernel = effective["kernel"]
    if (
        kernel["configuredArchiveDigest"] != configured_kernel["digest"][7:]
        or kernel["configuredArchiveUrl"] != configured_kernel["url"]
        or kernel["configuredBinaryPath"] != configured_kernel["binaryPath"]
    ):
        raise ProofPlaneError("Apple runtime kernel differs from effective configuration")

    init_image = value["initImage"]
    if not isinstance(init_image, Mapping):
        raise ProofPlaneError("Apple runtime initImage must be an object")
    exact_fields(
        init_image,
        (
            "configuredReference", "immutableReference", "indexDigest", "descriptorSha256",
            "stateFileSha256", "blobs", "blobCount", "totalBlobBytes", "closureSha256",
            "annotationShadowingAbsent",
        ),
        "Apple runtime initImage",
    )
    for name in ("indexDigest", "descriptorSha256", "stateFileSha256", "closureSha256"):
        _require_sha256(init_image[name], "Apple runtime initImage.%s" % name)
    blobs_value = init_image["blobs"]
    if not isinstance(blobs_value, list) or not 1 <= len(blobs_value) <= _MAX_OCI_BLOBS:
        raise ProofPlaneError("Apple runtime initImage blobs must be one bounded list")
    blobs = []
    for item in blobs_value:
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple runtime initImage blob evidence must be an object")
        exact_fields(
            item,
            ("digest", "bytes", "mediaType"),
            "Apple runtime initImage blob evidence",
        )
        digest = _require_sha256(item["digest"], "Apple runtime initImage blob digest")
        size = _require_count(
            item["bytes"], "Apple runtime initImage blob bytes", _MAX_OCI_BLOB_BYTES
        )
        if size < 1:
            raise ProofPlaneError("Apple runtime initImage blob must not be empty")
        media_type = item["mediaType"]
        if not isinstance(media_type, str) or _MEDIA_TYPE.fullmatch(media_type) is None:
            raise ProofPlaneError("Apple runtime initImage blob mediaType is invalid")
        blobs.append({"digest": digest, "bytes": size, "mediaType": media_type})
    blob_digests = [item["digest"] for item in blobs]
    if blob_digests != sorted(blob_digests) or len(set(blob_digests)) != len(blob_digests):
        raise ProofPlaneError("Apple runtime initImage blobs must be uniquely digest-sorted")
    index_blobs = [item for item in blobs if item["digest"] == init_image["indexDigest"]]
    if len(index_blobs) != 1 or index_blobs[0]["mediaType"] not in _INDEX_MEDIA_TYPES:
        raise ProofPlaneError("Apple runtime initImage index is absent from its blob closure")
    total_blob_bytes = sum(item["bytes"] for item in blobs)
    configured_reference = effective["vminit"]["image"]
    if (
        init_image["configuredReference"] != configured_reference
        or init_image["immutableReference"] != _immutable_reference(
            configured_reference, init_image["indexDigest"]
        )
        or init_image["annotationShadowingAbsent"] is not True
        or _require_count(
            init_image["blobCount"], "Apple runtime init blobCount", _MAX_OCI_BLOBS
        ) != len(blobs)
        or _require_count(
            init_image["totalBlobBytes"], "Apple runtime init totalBlobBytes", _MAX_OCI_TOTAL_BYTES
        ) != total_blob_bytes
        or init_image["closureSha256"] != canonical_digest(blobs)
    ):
        raise ProofPlaneError("Apple runtime initImage binding is invalid")

    _require_sha256(value["tcbSha256"], "Apple runtime TCB self-digest")
    body = {name: value[name] for name in fields if name != "tcbSha256"}
    if value["tcbSha256"] != canonical_digest(body):
        raise ProofPlaneError("Apple runtime TCB self-digest is invalid")
    # Canonical JSON round-trip returns detached built-in containers and also
    # rejects non-JSON values that Mapping subclasses could otherwise smuggle.
    normalized = _json(canonical_bytes(dict(value)), "Apple runtime TCB document", _MAX_STATE_BYTES)
    assert isinstance(normalized, dict)
    return normalized


def inspect_apple_container_tcb(runtime: Path) -> AppleRuntimeTCB:
    """Inspect one already-running Apple container 1.2.2 installation."""

    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise ProofPlaneError("Apple runtime TCB inspection requires arm64 macOS")
    if not isinstance(runtime, Path) or not runtime.is_absolute() or runtime.name != "container":
        raise ProofPlaneError("Apple container runtime must be an absolute container path")
    runtime_parent = _resolve_macos_root(runtime.parent, "Apple container CLI parent")
    runtime = runtime_parent / runtime.name
    initial_runtime = _file_evidence(runtime, "Apple container CLI", executable=True)

    version_argv = (str(runtime), "system", "version", "--format", "json")
    version_result = _run_command(version_argv, timeout_seconds=30, maximum_output_bytes=100_000)
    if version_result.returncode != 0 or version_result.stderr:
        raise ProofPlaneError("Apple container system version query failed")
    runtime_version, components = _version_components(version_result.stdout)

    status_argv = (str(runtime), "system", "status", "--format", "json")
    status_result = _run_command(status_argv, timeout_seconds=30, maximum_output_bytes=100_000)
    if status_result.returncode != 0 or status_result.stderr:
        raise ProofPlaneError("Apple container system status query failed")
    app_root, install_root, status = _status(status_result.stdout, components)
    expected_runtime = install_root / "bin" / "container"
    if runtime != expected_runtime:
        raise ProofPlaneError("Apple container CLI differs from the live installRoot")
    _closed_plugin_tree(install_root)

    property_argv = (str(runtime), "system", "property", "list", "--format", "json")
    property_result = _run_command(property_argv, timeout_seconds=30, maximum_output_bytes=_MAX_COMMAND_OUTPUT)
    if property_result.returncode != 0 or property_result.stderr:
        raise ProofPlaneError("Apple container effective-property query failed")
    effective_config = _property_config(property_result.stdout)

    installed = _installed_file_inventory(install_root)
    if installed[0]["relativePath"] != "bin/container" or installed[0]["sha256"] != initial_runtime["sha256"]:
        raise ProofPlaneError("Apple container CLI changed before installed-file inspection")

    override_directory = install_root / "libexec" / "container-plugins"
    if override_directory.exists() or override_directory.is_symlink():
        raise ProofPlaneError("Apple container override plugin directory must be absent")

    service_definitions = _service_definition_inventory(app_root, install_root, status)

    init_image = _init_image(app_root, effective_config["vminit"]["image"])
    kernel = _kernel(app_root, effective_config["kernel"])
    config_layers = _config_layer_inventory(app_root, install_root)
    body = {
        "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
        "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
        "platform": "macos/arm64",
        "assuranceScope": dict(_ASSURANCE_SCOPE),
        "runtime": {
            "name": "apple-container",
            "version": runtime_version,
            "binarySha256": initial_runtime["sha256"],
        },
        "versionQuery": {
            "commandSha256": canonical_digest(list(version_argv)),
            "process": _capture(version_result),
            "components": list(components),
        },
        "statusQuery": {
            "commandSha256": canonical_digest(list(status_argv)),
            "process": _capture(status_result),
            "status": status,
        },
        "propertyQuery": {
            "commandSha256": canonical_digest(list(property_argv)),
            "process": _capture(property_result),
            "effectiveConfig": effective_config,
            "effectiveConfigSha256": canonical_digest(effective_config),
        },
        "hostFiles": list(installed),
        "hostFilesSha256": canonical_digest(installed),
        "serviceDefinitions": list(service_definitions),
        "serviceDefinitionsSha256": canonical_digest(service_definitions),
        "configLayers": list(config_layers),
        "configLayersSha256": canonical_digest(config_layers),
        "kernel": kernel,
        "initImage": init_image,
        "userPluginOverrideDirectoryAbsent": True,
    }
    document = validate_apple_container_tcb_document(_self_digest(body))

    # Re-run the live queries and re-read every mutable authority represented
    # by the document before returning it.  This is a stability check over the
    # inspection interval, not an attestation of already-loaded processes or
    # unpacked VM snapshots.  Callers additionally compare complete snapshots
    # immediately before and after each scored run.
    final_version_result = _run_command(
        version_argv, timeout_seconds=30, maximum_output_bytes=100_000
    )
    if final_version_result.returncode != 0 or final_version_result.stderr:
        raise ProofPlaneError("Apple container final system version query failed")
    final_runtime_version, final_components = _version_components(final_version_result.stdout)
    if (
        final_runtime_version != runtime_version
        or final_components != components
        or _capture(final_version_result) != document["versionQuery"]["process"]
    ):
        raise ProofPlaneError("Apple container system version changed during TCB inspection")

    final_status_result = _run_command(
        status_argv, timeout_seconds=30, maximum_output_bytes=100_000
    )
    if final_status_result.returncode != 0 or final_status_result.stderr:
        raise ProofPlaneError("Apple container final system status query failed")
    final_app_root, final_install_root, final_status = _status(
        final_status_result.stdout, final_components
    )
    if (
        final_app_root != app_root
        or final_install_root != install_root
        or final_status != status
        or _capture(final_status_result) != document["statusQuery"]["process"]
    ):
        raise ProofPlaneError("Apple container system status changed during TCB inspection")

    final_property_result = _run_command(
        property_argv, timeout_seconds=30, maximum_output_bytes=_MAX_COMMAND_OUTPUT
    )
    if final_property_result.returncode != 0 or final_property_result.stderr:
        raise ProofPlaneError("Apple container final effective-property query failed")
    final_effective_config = _property_config(final_property_result.stdout)
    if (
        final_effective_config != effective_config
        or _capture(final_property_result) != document["propertyQuery"]["process"]
    ):
        raise ProofPlaneError("Apple container effective properties changed during TCB inspection")

    _closed_plugin_tree(install_root)
    if _installed_file_inventory(install_root) != installed:
        raise ProofPlaneError("Apple installed runtime files changed during TCB inspection")
    if override_directory.exists() or override_directory.is_symlink():
        raise ProofPlaneError("Apple container override plugin directory appeared during TCB inspection")
    if _service_definition_inventory(app_root, install_root, final_status) != service_definitions:
        raise ProofPlaneError("Apple service definitions changed during TCB inspection")
    if _config_layer_inventory(app_root, install_root) != config_layers:
        raise ProofPlaneError("Apple configuration layers changed during TCB inspection")
    if _kernel(app_root, final_effective_config["kernel"]) != kernel:
        raise ProofPlaneError("Apple managed kernel changed during TCB inspection")
    if _init_image(app_root, final_effective_config["vminit"]["image"]) != init_image:
        raise ProofPlaneError("Apple vminit image closure changed during TCB inspection")

    return AppleRuntimeTCB(
        document=document,
        tcb_sha256=document["tcbSha256"],
        runtime_version=runtime_version,
        runtime_binary_sha256=initial_runtime["sha256"],
        kernel_path=kernel["resolvedPath"],
        kernel_sha256=kernel["sha256"],
        immutable_init_image_reference=init_image["immutableReference"],
    )


__all__ = [
    "APPLE_RUNTIME_TCB_CONTRACT",
    "APPLE_RUNTIME_TCB_SCHEMA",
    "APPLE_RUNTIME_VERSION",
    "AppleRuntimeTCB",
    "inspect_apple_container_tcb",
    "validate_apple_container_tcb_document",
]
