#!/usr/bin/env python3
"""Install JStack commands, skills, and MCP server into Codex."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, NamedTuple, Optional

try:  # Python 3.11+
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - exercised by the Python 3.9 CI job
    _tomllib = None


PROMPTS = (
    "j-stack-dev.md",
    "jstack-subagents.md",
    "jstack-full-team.md",
    "jstack-audit.md",
    "jstack-loop.md",
)

AGENTS_BEGIN = b"<!-- BEGIN JSTACK PRODUCT UI (managed) -->"
AGENTS_END = b"<!-- END JSTACK PRODUCT UI (managed) -->"
MAX_AGENTS_BYTES = 2 * 1024 * 1024
MAX_INSTALL_CONTROL_FILE_BYTES = 2 * 1024 * 1024
MAX_PRODUCT_UI_SKILL_ENTRIES = 256
MAX_PRODUCT_UI_SKILL_FILE_BYTES = 1 * 1024 * 1024
MAX_PRODUCT_UI_SKILL_TOTAL_BYTES = 8 * 1024 * 1024
MAX_INSTALL_TREE_ENTRIES = 4_096
MAX_INSTALL_TREE_FILE_BYTES = 25 * 1024 * 1024
MAX_INSTALL_TREE_TOTAL_BYTES = 100 * 1024 * 1024
PRODUCT_UI_SKILL = "product-ui-design"
KNOWN_PRODUCT_UI_PLUGIN_NAMES = frozenset({"j-stack-dev", "jstack"})
PRODUCT_UI_OWNER_FILE = ".jstack-owner.json"
PRODUCT_UI_OWNER_CONTENT = (
    '{"owner":"jstack","schemaVersion":"jstack.direct-skill-owner.v1",'
    '"skill":"product-ui-design"}\n'
)


class ManagedAgentsError(RuntimeError):
    """Raised when the managed global instructions cannot be changed safely."""


class ManagedAgentsPreimageDrift(ManagedAgentsError):
    """Raised when AGENTS.md changes between inspection and replacement."""


class InstallPreimageDrift(RuntimeError):
    """Raised when an installer-owned target changes before activation."""


class InstallFileState(NamedTuple):
    exists: bool
    content: bytes
    stat_identity: Optional[tuple[int, int, int, int, int, int, int, int, int]]


class InstallTreeState(NamedTuple):
    exists: bool
    entries: tuple[tuple[str, str, bytes, tuple[int, int, int, int, int, int, int, int, int]], ...]
    stat_identity: Optional[tuple[int, int, int, int, int, int, int, int, int]]


class ManagedAgentsPreimage(NamedTuple):
    path: Path
    exists: bool
    content: bytes
    stat_identity: Optional[tuple[int, int, int, int, int, int, int, int, int]]
    parent_path: Path
    parent_identity: tuple[int, int, int, int]


def _current_uid() -> Optional[int]:
    return os.geteuid() if hasattr(os, "geteuid") else None


def _stat_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        int(getattr(value, "st_file_attributes", 0)),
        int(getattr(value, "st_reparse_tag", 0)),
    )


def _set_open_file_mode(descriptor: int, path: Path, mode: int) -> None:
    """Set a staged file's mode without requiring POSIX-only ``os.fchmod``."""
    fchmod = getattr(os, "fchmod", None)
    if callable(fchmod):
        fchmod(descriptor, mode)
        return

    # Windows has no os.fchmod on supported Python versions. The staged path
    # is an unpredictable O_EXCL file, but still bind the path-based fallback
    # to the already-open regular file before and after chmod so replacement
    # races fail closed. POSIX hosts that lack fchmod retain exact mode checks.
    before = os.fstat(descriptor)
    entry_before = os.lstat(path)
    before_identity = (before.st_dev, before.st_ino)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or _is_link_or_reparse(entry_before)
        or not stat.S_ISREG(entry_before.st_mode)
        or entry_before.st_nlink != 1
        or (entry_before.st_dev, entry_before.st_ino) != before_identity
    ):
        raise RuntimeError(f"Staged installer file changed before chmod: {path}")

    if os.chmod in getattr(os, "supports_follow_symlinks", ()):
        os.chmod(path, mode, follow_symlinks=False)
    else:
        os.chmod(path, mode)

    after = os.fstat(descriptor)
    entry_after = os.lstat(path)
    if (
        not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or _is_link_or_reparse(entry_after)
        or not stat.S_ISREG(entry_after.st_mode)
        or entry_after.st_nlink != 1
        or (after.st_dev, after.st_ino) != before_identity
        or (entry_after.st_dev, entry_after.st_ino) != before_identity
    ):
        raise RuntimeError(f"Staged installer file changed during chmod: {path}")
    if os.name == "posix" and stat.S_IMODE(after.st_mode) != mode:
        raise RuntimeError(f"Staged installer file mode could not be set safely: {path}")


def _windows_acl_required() -> bool:
    """Return whether Windows DACL validation is required for this install."""

    # Descriptor chmod availability says nothing about Windows DACL privacy.
    # Keep this boundary independent so Python versions that expose fchmod in
    # the future still receive the same fail-closed ACL validation.
    return os.name == "nt"


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(marker and getattr(metadata, "st_file_attributes", 0) & marker)
        or bool(getattr(metadata, "st_reparse_tag", 0))
    )


def _path_is_link_or_reparse(path: Path) -> bool:
    try:
        return _is_link_or_reparse(os.lstat(path))
    except FileNotFoundError:
        return False


def _validate_existing_ancestry(path: Path, *, label: str) -> None:
    current = _absolute_without_resolving(path)
    filesystem_root = Path(current.anchor)
    while True:
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            pass
        else:
            root_owned_posix_alias = bool(
                os.name == "posix"
                and current.parent == filesystem_root
                and getattr(metadata, "st_uid", None) == 0
            )
            if _is_link_or_reparse(metadata) and not root_owned_posix_alias:
                raise RuntimeError(
                    f"Refusing linked or reparse-point {label} ancestry: {current}"
                )
        if current == current.parent:
            return
        current = current.parent


def _run_windows_acl_script(
    script: str,
    environment: dict[str, str],
    *,
    label: str,
    input_text: Optional[str] = None,
) -> None:
    process_environment = dict(os.environ)
    process_environment.update(environment)
    run_input = None if input_text is None else input_text.encode("utf-8")
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            stdin=subprocess.DEVNULL if run_input is None else None,
            input=run_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_environment,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            f"Could not verify the Windows ACL for {label}; installation stopped safely."
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"The Windows ACL for {label} is not verifiably user-private; installation stopped safely."
        )


def _windows_private_acl_script(invocation: str) -> str:
    return r"""
$ErrorActionPreference = 'Stop'
function Assert-JStackPrivateAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @($current, 'S-1-5-18', 'S-1-5-32-544')
    $owner = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    if ($allowed -notcontains $owner) {
        exit 22
    }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        $creatorOwner = (
            $sid -eq 'S-1-3-0' -and
            ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)
        )
        if (($allowed -notcontains $sid) -and -not $creatorOwner) {
            exit 23
        }
    }
}
""" + invocation


def _ensure_windows_private_acl(path: Path, *, label: str) -> None:
    if not _windows_acl_required():
        return
    script = _windows_private_acl_script(
        "\nAssert-JStackPrivateAcl -Path $env:JSTACK_ACL_PATH\n"
    )
    _run_windows_acl_script(
        script,
        {"JSTACK_ACL_PATH": str(path)},
        label=label,
    )


def _ensure_windows_private_acls(paths: list[Path], *, label: str) -> None:
    """Validate a bounded path set with one PowerShell process."""

    if not _windows_acl_required() or not paths:
        return
    script = _windows_private_acl_script(
        r"""
$paths = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
foreach ($path in @($paths)) {
    Assert-JStackPrivateAcl -Path $path
}
"""
    )
    # Windows PowerShell 5.1 reads redirected console input through the active
    # code page. JSON ASCII escapes keep non-ASCII profile paths lossless.
    payload = json.dumps([str(path) for path in paths])
    try:
        payload.encode("ascii")
    except UnicodeError as exc:
        raise RuntimeError(
            f"Could not encode Windows ACL paths for {label}; installation stopped safely."
        ) from exc
    _run_windows_acl_script(
        script,
        {},
        label=label,
        input_text=payload,
    )


def _windows_profile_root() -> Path:
    raw = os.environ.get("USERPROFILE")
    if not raw:
        raise RuntimeError(
            "Windows installation requires a verifiable current-user profile root."
        )
    return _absolute_without_resolving(Path(raw))


def _validate_windows_install_root(codex_home: Path) -> None:
    if not _windows_acl_required():
        return
    _validate_existing_ancestry(codex_home, label="Codex home")
    home = _absolute_without_resolving(codex_home)
    profile = _windows_profile_root()
    try:
        common = os.path.commonpath((os.fspath(profile), os.fspath(home)))
    except ValueError as exc:
        raise RuntimeError(
            "Windows CODEX_HOME must be inside the current-user profile."
        ) from exc
    if os.path.normcase(common) != os.path.normcase(os.fspath(profile)):
        raise RuntimeError(
            "Windows CODEX_HOME must be inside the current-user profile."
        )
    try:
        relative = home.relative_to(profile)
    except ValueError as exc:
        raise RuntimeError(
            "Windows CODEX_HOME must be inside the current-user profile."
        ) from exc
    current = profile
    candidates = [profile]
    for part in relative.parts:
        current /= part
        candidates.append(current)
    found_missing = False
    for current in candidates:
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            found_missing = True
            continue
        if found_missing:
            raise RuntimeError(
                "Windows CODEX_HOME ancestry changed during validation."
            )
        if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(
                "The Windows Codex home ancestry must be real non-reparse directories."
            )
        _ensure_windows_private_acl(
            current,
            label=f"Codex home ancestry {current}",
        )


def _validate_windows_managed_path(
    codex_home: Path,
    path: Path,
    *,
    label: str,
) -> None:
    """Validate every existing managed descendant, not just CODEX_HOME itself."""

    if not _windows_acl_required():
        return
    root = _absolute_without_resolving(codex_home)
    candidate = _absolute_without_resolving(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"Windows {label} must remain inside CODEX_HOME.") from exc
    current = root
    missing = False
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            missing = True
            continue
        if missing:
            raise RuntimeError(f"Windows {label} ancestry changed during validation.")
        if _is_link_or_reparse(metadata):
            raise RuntimeError(
                f"Windows {label} requires real non-reparse descendants: {current}"
            )
        is_final = index == len(relative.parts) - 1
        if not is_final and not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"Windows {label} ancestry is not a directory: {current}")
        _ensure_windows_private_acl(
            current,
            label=f"{label} {current}",
        )


def _preserve_windows_file_acl(source: Path, destination: Path) -> None:
    if not _windows_acl_required():
        return
    _validate_existing_ancestry(source, label="Windows ACL source")
    _validate_existing_ancestry(destination, label="Windows ACL destination")
    if source.exists() or _path_is_link_or_reparse(source):
        source_metadata = os.lstat(source)
        if (
            _is_link_or_reparse(source_metadata)
            or not stat.S_ISREG(source_metadata.st_mode)
        ):
            raise RuntimeError(
                f"Refusing to copy a Windows ACL from an unsafe file: {source}"
            )
        script = r"""
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $env:JSTACK_ACL_SOURCE
Set-Acl -LiteralPath $env:JSTACK_ACL_DESTINATION -AclObject $acl
"""
        _run_windows_acl_script(
            script,
            {
                "JSTACK_ACL_SOURCE": str(source),
                "JSTACK_ACL_DESTINATION": str(destination),
            },
            label=f"staged replacement for {source.name}",
        )
    _ensure_windows_private_acl(
        destination,
        label=f"staged replacement for {source.name}",
    )


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _validate_managed_parent(path: Path) -> tuple[Path, os.stat_result]:
    try:
        _validate_existing_ancestry(path.parent, label="managed AGENTS.md parent")
    except RuntimeError as exc:
        raise ManagedAgentsError(str(exc)) from exc
    current = _absolute_without_resolving(path.parent)
    while True:
        try:
            value = os.lstat(current)
            break
        except FileNotFoundError:
            if current == current.parent:  # pragma: no cover
                raise ManagedAgentsError(f"No existing parent for managed path: {path}")
            current = current.parent
    uid = _current_uid()
    if _is_link_or_reparse(value):
        raise ManagedAgentsError(
            f"Refusing managed AGENTS.md linked or reparse-point parent: {current}"
        )
    if not stat.S_ISDIR(value.st_mode):
        raise ManagedAgentsError(f"Managed AGENTS.md parent is not a directory: {current}")
    if uid is not None and value.st_uid != uid:
        raise ManagedAgentsError(
            f"Managed AGENTS.md parent ownership mismatch: {current}"
        )
    return current, value


def _read_regular_file(
    path: Path,
    *,
    label: str = "Managed AGENTS.md",
    max_bytes: Optional[int] = MAX_AGENTS_BYTES,
) -> tuple[bytes, os.stat_result]:
    try:
        _validate_existing_ancestry(path, label=label)
        entry_before = os.lstat(path)
    except (OSError, RuntimeError) as exc:
        raise ManagedAgentsError(f"Unable to inspect {label} safely: {path}") from exc
    if _is_link_or_reparse(entry_before) or not stat.S_ISREG(entry_before.st_mode):
        raise ManagedAgentsError(f"{label} is not a safe regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManagedAgentsError(f"Unable to open {label} safely: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino)
            != (entry_before.st_dev, entry_before.st_ino)
        ):
            raise ManagedAgentsError(f"{label} is not a regular file: {path}")
        if max_bytes is not None and before.st_size > max_bytes:
            raise ManagedAgentsError(
                f"{label} exceeds the {max_bytes}-byte safety limit: {path}"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise ManagedAgentsError(
                    f"{label} exceeds the {max_bytes}-byte safety limit: {path}"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise ManagedAgentsPreimageDrift(
                f"{label} changed while being read: {path}"
            )
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _inspect_install_file(path: Path, *, label: str) -> InstallFileState:
    path = _absolute_without_resolving(path)
    try:
        _validate_existing_ancestry(path, label=label)
    except RuntimeError as exc:
        raise ManagedAgentsError(str(exc)) from exc
    try:
        target = os.lstat(path)
    except FileNotFoundError:
        return InstallFileState(False, b"", None)
    if _is_link_or_reparse(target):
        raise ManagedAgentsError(f"Refusing linked or reparse-point {label}: {path}")
    if not stat.S_ISREG(target.st_mode):
        raise ManagedAgentsError(f"{label} is not a regular file: {path}")
    content, opened = _read_regular_file(
        path, label=label, max_bytes=MAX_INSTALL_CONTROL_FILE_BYTES
    )
    if _stat_identity(target) != _stat_identity(opened):
        raise InstallPreimageDrift(f"{label} changed during inspection: {path}")
    return InstallFileState(True, content, _stat_identity(opened))


def _install_file_state_matches(path: Path, expected: InstallFileState) -> bool:
    try:
        current = _inspect_install_file(path, label="install target")
    except (ManagedAgentsError, InstallPreimageDrift):
        return False
    return current == expected


def _verify_install_file_state(
    path: Path,
    expected: InstallFileState,
    *,
    label: str,
) -> None:
    if not _install_file_state_matches(path, expected):
        raise InstallPreimageDrift(f"{label} changed after installer preflight: {path}")


def _move_file_noreplace(source: Path, target: Path, *, label: str) -> None:
    """Atomically move one file without replacing a raced destination."""

    _validate_existing_ancestry(target, label=label)
    _rename_path_noreplace(source, target)


def _restore_or_retain_file(
    displaced: Path,
    target: Path,
    retained: Optional[Path],
    *,
    label: str,
) -> bool:
    """Restore a displaced file, or retain it when the target was recreated."""

    try:
        _move_file_noreplace(displaced, target, label=label)
        return False
    except (OSError, RuntimeError):
        if retained is None:
            return True
    assert retained is not None
    try:
        _move_file_noreplace(
            displaced,
            retained,
            label="retained installer preimage",
        )
        return False
    except (OSError, RuntimeError):
        return True


def _activate_staged_file_cas(
    temporary: Path,
    path: Path,
    expected: InstallFileState,
    *,
    label: str,
    retain_preimage: Optional[Path] = None,
) -> InstallFileState:
    """Activate a staged file without overwriting a changed or newly appeared target."""
    displaced = path.parent / f".{path.name}.jstack-displaced-{uuid.uuid4().hex}"
    moved = False
    try:
        try:
            _move_file_noreplace(path, displaced, label=label)
            moved = True
        except FileNotFoundError:
            moved = False
        except (OSError, RuntimeError) as exc:
            raise InstallPreimageDrift(
                f"{label} could not be displaced safely: {path}"
            ) from exc
        except BaseException:
            destination_present = (
                displaced.exists() or _path_is_link_or_reparse(displaced)
            )
            moved = destination_present
            raise
        if moved:
            try:
                observed = _inspect_install_file(displaced, label=label)
            except (ManagedAgentsError, InstallPreimageDrift):
                observed = None
            if not expected.exists or observed != expected:
                moved = _restore_or_retain_file(
                    displaced,
                    path,
                    retain_preimage,
                    label=label,
                )
                raise InstallPreimageDrift(
                    f"{label} changed during atomic activation: {path}"
                )
        elif expected.exists:
            raise InstallPreimageDrift(
                f"{label} disappeared during atomic activation: {path}"
            )
        try:
            _move_file_noreplace(
                temporary,
                path,
                label=label,
            )
        except (FileExistsError, OSError) as exc:
            if moved and (
                displaced.exists() or _path_is_link_or_reparse(displaced)
            ):
                moved = _restore_or_retain_file(
                    displaced,
                    path,
                    retain_preimage,
                    label=label,
                )
            raise InstallPreimageDrift(
                f"{label} changed during atomic activation: {path}"
            ) from exc
        postimage = _inspect_install_file(path, label=label)
        if moved:
            # Recheck the displaced preimage before discarding it; this catches
            # a writer that raced the displacement using an already-open fd.
            if _inspect_install_file(displaced, label=label) != expected:
                if retain_preimage is not None:
                    try:
                        _move_file_noreplace(
                            displaced,
                            retain_preimage,
                            label="retained installer preimage",
                        )
                        moved = False
                    except (OSError, RuntimeError):
                        pass
                raise InstallPreimageDrift(
                    f"{label} preimage changed during atomic activation; "
                    "the live target and recoverable preimage were preserved"
                )
            if retain_preimage is None:
                raise InstallPreimageDrift(
                    f"{label} needs a durable preimage retention path: {path}"
                )
            _move_file_noreplace(
                displaced,
                retain_preimage,
                label="retained installer preimage",
            )
            moved = False
        return postimage
    finally:
        if temporary.exists():
            temporary.unlink()
        if moved and (displaced.exists() or _path_is_link_or_reparse(displaced)):
            _restore_or_retain_file(
                displaced,
                path,
                retain_preimage,
                label=label,
            )


def _validate_marker_line(content: bytes, position: int, marker: bytes) -> None:
    if position > 0 and content[position - 1 : position] not in {b"\n", b"\r"}:
        raise ManagedAgentsError("Managed AGENTS.md marker is not on its own line")
    after = position + len(marker)
    if after < len(content) and content[after : after + 1] not in {b"\n", b"\r"}:
        raise ManagedAgentsError("Managed AGENTS.md marker is not on its own line")


def _agents_newline(content: bytes, begin_position: Optional[int] = None) -> bytes:
    if begin_position is not None:
        after = begin_position + len(AGENTS_BEGIN)
        if content[after : after + 2] == b"\r\n":
            return b"\r\n"
        if content[after : after + 1] in {b"\n", b"\r"}:
            return content[after : after + 1]
    crlf_count = content.count(b"\r\n")
    lf_count = content.count(b"\n") - crlf_count
    cr_count = content.count(b"\r") - crlf_count
    if crlf_count >= max(lf_count, cr_count) and crlf_count:
        return b"\r\n"
    if cr_count > lf_count:
        return b"\r"
    return b"\n"


def managed_agents_block(newline: bytes) -> bytes:
    lines = (
        AGENTS_BEGIN,
        b"## JStack Product UI",
        b"",
        b"For user-facing interface work, use the installed `product-ui-design` skill automatically.",
        b"Apply it only to UI scope; backend-only and non-interface work remain unaffected.",
        b"Explicit user instructions and an existing project design system, tokens, components,",
        b"layouts, accessibility rules, and brand rules take precedence and must be preserved.",
        b"This managed guidance grants no additional authority for tools, file writes, subagents,",
        b"network access, external actions, release, deployment, or production access.",
        AGENTS_END,
    )
    return newline.join(lines)


def render_managed_agents(content: bytes) -> bytes:
    if len(content) > MAX_AGENTS_BYTES:
        raise ManagedAgentsError(
            f"Managed AGENTS.md exceeds the {MAX_AGENTS_BYTES}-byte safety limit"
        )
    begin_count = content.count(AGENTS_BEGIN)
    end_count = content.count(AGENTS_END)
    if begin_count != end_count or begin_count not in {0, 1}:
        raise ManagedAgentsError(
            "Managed AGENTS.md has half, duplicate, or nested JStack markers"
        )
    if begin_count == 1:
        begin = content.find(AGENTS_BEGIN)
        end = content.find(AGENTS_END)
        if end <= begin:
            raise ManagedAgentsError(
                "Managed AGENTS.md has reversed or nested JStack markers"
            )
        _validate_marker_line(content, begin, AGENTS_BEGIN)
        _validate_marker_line(content, end, AGENTS_END)
        newline = _agents_newline(content, begin)
        replacement_end = end + len(AGENTS_END)
        return content[:begin] + managed_agents_block(newline) + content[replacement_end:]

    newline = _agents_newline(content)
    block = managed_agents_block(newline)
    if not content:
        return block + newline
    separator = newline if content.endswith((b"\n", b"\r")) else newline + newline
    return content + separator + block + newline


def inspect_managed_agents(path: Path) -> ManagedAgentsPreimage:
    path = _absolute_without_resolving(path)
    parent_path, parent = _validate_managed_parent(path)
    try:
        target = os.lstat(path)
    except FileNotFoundError:
        content = b""
        identity = None
        exists = False
    else:
        if _is_link_or_reparse(target):
            raise ManagedAgentsError(
                f"Refusing to manage linked or reparse-point AGENTS.md: {path}"
            )
        if not stat.S_ISREG(target.st_mode):
            raise ManagedAgentsError(f"Managed AGENTS.md is not a regular file: {path}")
        uid = _current_uid()
        if uid is not None and target.st_uid != uid:
            raise ManagedAgentsError(f"Managed AGENTS.md ownership mismatch: {path}")
        content, opened = _read_regular_file(path)
        if _stat_identity(target) != _stat_identity(opened):
            raise ManagedAgentsPreimageDrift(
                f"Managed AGENTS.md changed during preflight: {path}"
            )
        identity = _stat_identity(opened)
        exists = True
    render_managed_agents(content)
    return ManagedAgentsPreimage(
        path=path,
        exists=exists,
        content=content,
        stat_identity=identity,
        parent_path=parent_path,
        parent_identity=(parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode),
    )


def _verify_managed_preimage(preimage: ManagedAgentsPreimage) -> None:
    _validate_managed_parent(preimage.path)
    try:
        parent = os.lstat(preimage.parent_path)
    except FileNotFoundError as exc:
        raise ManagedAgentsPreimageDrift(
            f"Managed AGENTS.md parent disappeared after preflight: {preimage.parent_path}"
        ) from exc
    parent_identity = (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode)
    if parent_identity != preimage.parent_identity:
        raise ManagedAgentsPreimageDrift(
            f"Managed AGENTS.md parent changed after preflight: {preimage.path.parent}"
        )
    try:
        target = os.lstat(preimage.path)
    except FileNotFoundError:
        if preimage.exists:
            raise ManagedAgentsPreimageDrift(
                f"Managed AGENTS.md disappeared after preflight: {preimage.path}"
            )
        return
    if not preimage.exists:
        raise ManagedAgentsPreimageDrift(
            f"Managed AGENTS.md appeared after preflight: {preimage.path}"
        )
    if _is_link_or_reparse(target) or not stat.S_ISREG(target.st_mode):
        raise ManagedAgentsPreimageDrift(
            f"Managed AGENTS.md type changed after preflight: {preimage.path}"
        )
    content, opened = _read_regular_file(preimage.path)
    if _stat_identity(opened) != preimage.stat_identity or content != preimage.content:
        raise ManagedAgentsPreimageDrift(
            f"Managed AGENTS.md changed after preflight: {preimage.path}"
        )


def write_managed_agents(
    preimage: ManagedAgentsPreimage,
    *,
    retain_preimage: Optional[Path] = None,
) -> InstallFileState:
    _verify_managed_preimage(preimage)
    current_parent_path, current_parent = _validate_managed_parent(preimage.path)
    current_parent_identity = (
        current_parent.st_dev,
        current_parent.st_ino,
        current_parent.st_uid,
        current_parent.st_mode,
    )
    content = render_managed_agents(preimage.content)
    mode = stat.S_IMODE(preimage.stat_identity[2]) if preimage.stat_identity else 0o644
    uid = preimage.stat_identity[3] if preimage.stat_identity else _current_uid()
    gid = (
        preimage.stat_identity[4]
        if preimage.stat_identity
        else (os.getgid() if hasattr(os, "getgid") else None)
    )
    preimage.path.parent.mkdir(parents=True, exist_ok=True)
    _validate_managed_parent(preimage.path)
    temporary = preimage.path.parent / f".{preimage.path.name}.jstack-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:  # pragma: no cover - regular local files make progress
                    raise ManagedAgentsError("Managed AGENTS.md write made no progress")
                offset += written
            os.fsync(descriptor)
            if uid is not None and gid is not None and hasattr(os, "fchown"):
                os.fchown(descriptor, uid, gid)
            _set_open_file_mode(descriptor, temporary, mode)
            _preserve_windows_file_acl(preimage.path, temporary)
        finally:
            os.close(descriptor)
            descriptor = None
        _verify_managed_preimage(preimage)
        verified_parent_path, verified_parent = _validate_managed_parent(preimage.path)
        verified_parent_identity = (
            verified_parent.st_dev,
            verified_parent.st_ino,
            verified_parent.st_uid,
            verified_parent.st_mode,
        )
        if (
            verified_parent_path != current_parent_path
            or verified_parent_identity != current_parent_identity
        ):
            raise ManagedAgentsPreimageDrift(
                f"Managed AGENTS.md parent changed before replacement: {preimage.path.parent}"
            )
        expected = InstallFileState(
            preimage.exists,
            preimage.content,
            preimage.stat_identity,
        )
        return _activate_staged_file_cas(
            temporary,
            preimage.path,
            expected,
            label="Managed AGENTS.md",
            retain_preimage=retain_preimage,
        )
    finally:
        if descriptor is not None:  # pragma: no cover - defensive close on unusual failures
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


_TOML_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


def _decode_toml_basic_key(value: str) -> str:
    escapes = {
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "f": "\f",
        "r": "\r",
        '"': '"',
        "\\": "\\",
    }
    output: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            if ord(character) < 0x20 or ord(character) == 0x7F:
                raise ValueError("invalid control character in TOML basic key")
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise ValueError("unterminated TOML basic-key escape")
        escape = value[index]
        if escape in escapes:
            output.append(escapes[escape])
            index += 1
            continue
        if escape not in {"u", "U"}:
            raise ValueError("invalid TOML basic-key escape")
        width = 4 if escape == "u" else 8
        digits = value[index + 1 : index + 1 + width]
        if len(digits) != width or any(
            character not in "0123456789abcdefABCDEF" for character in digits
        ):
            raise ValueError("invalid TOML Unicode escape")
        codepoint = int(digits, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError("invalid TOML Unicode scalar value")
        output.append(chr(codepoint))
        index += 1 + width
    return "".join(output)


def _toml_key_parts(value: str) -> tuple[str, ...]:
    """Parse TOML dotted keys for the Python 3.9 plugin-only fallback."""

    parts: list[str] = []
    index = 0
    while True:
        while index < len(value) and value[index].isspace():
            index += 1
        if index >= len(value):
            if parts:
                return tuple(parts)
            raise ValueError("empty TOML key")
        if value[index] == '"':
            start = index
            index += 1
            escaped = False
            while index < len(value):
                character = value[index]
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    index += 1
                    break
                index += 1
            else:
                raise ValueError("unterminated TOML basic key")
            part = _decode_toml_basic_key(value[start + 1 : index - 1])
        elif value[index] == "'":
            end = value.find("'", index + 1)
            if end < 0:
                raise ValueError("unterminated TOML literal key")
            part = value[index + 1 : end]
            index = end + 1
        else:
            match = _TOML_BARE_KEY.match(value, index)
            if match is None:
                raise ValueError("invalid TOML bare key")
            part = match.group(0)
            index = match.end()
        parts.append(part)
        while index < len(value) and value[index].isspace():
            index += 1
        if index == len(value):
            return tuple(parts)
        if value[index] != ".":
            raise ValueError("invalid TOML dotted key")
        index += 1


def _toml_without_comment(line: str) -> str:
    quote: Optional[str] = None
    escaped = False
    for index, character in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "#":
            return line[:index]
    return line


def _toml_square_bracket_delta(value: str) -> int:
    """Count TOML array brackets outside single-line strings and comments."""

    quote: Optional[str] = None
    escaped = False
    delta = 0
    for character in value:
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "#":
            break
        elif character == "[":
            delta += 1
        elif character == "]":
            delta -= 1
    return delta


def _split_toml_assignment(line: str) -> tuple[str, str]:
    quote: Optional[str] = None
    escaped = False
    for index, character in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "=":
            return line[:index], line[index + 1 :]
    raise ValueError("TOML assignment is missing '='")


def _split_inline_fields(value: str) -> list[str]:
    fields: list[str] = []
    start = 0
    quote: Optional[str] = None
    escaped = False
    depth = 0
    for index, character in enumerate(value):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "[{(":
            depth += 1
        elif character in "]})":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            fields.append(value[start:index])
            start = index + 1
    fields.append(value[start:])
    return fields


def _fallback_inline_enabled(value: str) -> Optional[bool]:
    stripped = value.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    seen: set[tuple[str, ...]] = set()
    enabled: Optional[bool] = None
    for field in _split_inline_fields(stripped[1:-1]):
        if not field.strip():
            continue
        try:
            key, raw_value = _split_toml_assignment(field)
            parts = _toml_key_parts(key)
        except ValueError as exc:
            raise ValueError("invalid plugin inline table") from exc
        if parts in seen:
            raise ValueError("duplicate plugin inline-table key")
        seen.add(parts)
        if parts == ("enabled",):
            normalized = raw_value.strip()
            if normalized == "false":
                enabled = False
            elif normalized == "true":
                enabled = True
            else:
                raise ValueError("plugin enabled must be boolean")
    return enabled


def _fallback_root_plugins(value: str) -> dict[str, bool]:
    """Parse the closed root `plugins = { ... }` shape used by Codex."""
    stripped = value.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        raise ValueError("plugins must be a table")
    states: dict[str, bool] = {}
    for field in _split_inline_fields(stripped[1:-1]):
        if not field.strip():
            continue
        try:
            raw_key, raw_value = _split_toml_assignment(field)
            key = _toml_key_parts(raw_key)
        except ValueError as exc:
            raise ValueError("invalid root plugins inline table") from exc
        if len(key) != 1 or key[0] in states:
            raise ValueError("duplicate or nested root plugin key")
        normalized_value = raw_value.strip()
        if not (
            normalized_value.startswith("{")
            and normalized_value.endswith("}")
        ):
            raise ValueError("root plugin value must be an inline table")
        enabled = _fallback_inline_enabled(raw_value)
        states[key[0]] = True if enabled is None else enabled
    return states


def _active_plugin_ids_fallback(config: str) -> set[str]:
    """Project the semantic plugins table without requiring Python 3.11."""

    states: dict[str, bool] = {}
    current_table: tuple[str, ...] = ()
    current_array_instance: Optional[int] = None
    next_array_instance = 0
    active_array_instances: dict[tuple[str, ...], int] = {}
    multiline: Optional[str] = None
    array_depth = 0
    seen_tables: set[tuple[Optional[int], tuple[str, ...]]] = set()
    implicit_tables: set[tuple[Optional[int], tuple[str, ...]]] = set()
    deferred_parent_tables: set[tuple[Optional[int], tuple[str, ...]]] = set()
    seen_keys: set[tuple[Optional[int], tuple[str, ...]]] = set()
    sealed_plugin_ids: set[str] = set()

    def active_array_instance(table: tuple[str, ...]) -> Optional[int]:
        matches = [
            (len(array_table), instance)
            for array_table, instance in active_array_instances.items()
            if len(table) >= len(array_table)
            and table[: len(array_table)] == array_table
        ]
        if not matches:
            return None
        return max(matches)[1]

    for raw_line in config.splitlines():
        if multiline is not None:
            if multiline in raw_line:
                multiline = None
            continue
        if array_depth:
            array_depth += _toml_square_bracket_delta(raw_line)
            if array_depth < 0:
                raise RuntimeError("Unable to parse Codex plugin multiline array")
            continue
        line = _toml_without_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]" ):
            header = line[2:-2]
            try:
                current_table = _toml_key_parts(header)
            except ValueError as exc:
                if "plugins" in header:
                    raise RuntimeError("Unable to parse Codex plugin configuration") from exc
                current_table = ()
            if current_table and current_table[0] == "plugins":
                raise RuntimeError(
                    "Codex plugin configuration may not use array-of-table declarations"
                )
            for array_table in tuple(active_array_instances):
                if (
                    len(array_table) >= len(current_table)
                    and array_table[: len(current_table)] == current_table
                ):
                    del active_array_instances[array_table]
            current_array_instance = next_array_instance
            active_array_instances[current_table] = current_array_instance
            next_array_instance += 1
            continue
        if line.startswith("[") and line.endswith("]"):
            header = line[1:-1]
            try:
                current_table = _toml_key_parts(header)
            except ValueError as exc:
                if "plugins" in header:
                    raise RuntimeError("Unable to parse Codex plugin configuration") from exc
                current_table = ()
            current_array_instance = active_array_instance(current_table)
            table_key = (current_array_instance, current_table)
            if table_key in seen_tables or (
                table_key in implicit_tables
                and table_key not in deferred_parent_tables
            ):
                raise RuntimeError("Duplicate or implicitly redefined TOML table")
            implicit_tables.discard(table_key)
            deferred_parent_tables.discard(table_key)
            seen_tables.add(table_key)
            for depth in range(1, len(current_table)):
                scoped_parent = (current_array_instance, current_table[:depth])
                if scoped_parent not in seen_tables:
                    implicit_tables.add(scoped_parent)
                    deferred_parent_tables.add(scoped_parent)
            if current_table and current_table[0] == "plugins":
                if len(current_table) >= 2 and current_table[1] in sealed_plugin_ids:
                    raise RuntimeError("Codex plugin table redefines an inline plugin value")
                if len(current_table) >= 2:
                    states.setdefault(current_table[1], True)
            continue
        try:
            raw_key, raw_value = _split_toml_assignment(line)
            key = _toml_key_parts(raw_key)
        except ValueError as exc:
            if current_table and current_table[0] == "plugins":
                raise RuntimeError("Unable to parse Codex plugin configuration") from exc
            continue
        array_depth = _toml_square_bracket_delta(raw_value)
        if array_depth < 0:
            raise RuntimeError("Unable to parse Codex plugin multiline array")
        full_key = current_table + key
        scoped_key = (current_array_instance, full_key)
        if scoped_key in seen_keys:
            raise RuntimeError("Duplicate TOML configuration key")
        seen_keys.add(scoped_key)
        for depth in range(1, len(full_key)):
            prefix = full_key[:depth]
            scoped_prefix = (current_array_instance, prefix)
            if scoped_prefix not in seen_tables:
                implicit_tables.add(scoped_prefix)
        if full_key == ("plugins",):
            try:
                root_plugins = _fallback_root_plugins(raw_value)
            except ValueError as exc:
                raise RuntimeError("Unable to parse Codex plugin configuration") from exc
            if any(
                table and table[0] == "plugins"
                for _scope, table in seen_tables | implicit_tables
            ) or states:
                raise RuntimeError("Codex plugins table is defined more than once")
            implicit_tables.add((None, ("plugins",)))
            for plugin_id, enabled in root_plugins.items():
                implicit_tables.add((None, ("plugins", plugin_id)))
                sealed_plugin_ids.add(plugin_id)
                states[plugin_id] = enabled
            continue
        if len(full_key) >= 2 and full_key[0] == "plugins":
            plugin_id = full_key[1]
            if plugin_id in sealed_plugin_ids and len(full_key) > 2:
                raise RuntimeError("Codex plugin key extends an inline plugin value")
            if len(full_key) == 2 and any(
                table[:2] == ("plugins", plugin_id)
                for _scope, table in seen_tables
                if len(table) >= 2
            ):
                raise RuntimeError("Codex plugin value redefines an existing plugin table")
            states.setdefault(plugin_id, True)
            if len(full_key) == 2:
                try:
                    enabled = _fallback_inline_enabled(raw_value)
                except ValueError as exc:
                    raise RuntimeError("Unable to parse Codex plugin configuration") from exc
                if enabled is not None:
                    states[plugin_id] = enabled
                sealed_plugin_ids.add(plugin_id)
            elif full_key[2:] == ("enabled",):
                normalized = raw_value.strip()
                if normalized == "false":
                    states[plugin_id] = False
                elif normalized == "true":
                    states[plugin_id] = True
                else:
                    raise RuntimeError("Codex plugin enabled value must be boolean")
        for delimiter in ('"""', "'''"):
            if raw_value.count(delimiter) % 2:
                multiline = delimiter
                break
    if array_depth:
        raise RuntimeError("Unable to parse Codex plugin unterminated multiline array")
    return {plugin_id for plugin_id, enabled in states.items() if enabled}


def _active_plugin_ids(config: str) -> set[str]:
    if _tomllib is None:
        return _active_plugin_ids_fallback(config)
    try:
        parsed = _tomllib.loads(config)
    except Exception as exc:
        raise RuntimeError("Unable to parse Codex config.toml safely") from exc
    plugins = parsed.get("plugins", {})
    if not isinstance(plugins, dict):
        raise RuntimeError("Codex config.toml plugins value must be a table")
    active: set[str] = set()
    for plugin_id, plugin_config in plugins.items():
        if not isinstance(plugin_id, str):  # pragma: no cover - TOML keys are strings
            raise RuntimeError("Codex plugin identifier must be text")
        enabled = plugin_config.get("enabled", True) if isinstance(plugin_config, dict) else True
        if enabled is not False:
            active.add(plugin_id)
    return active


def active_product_ui_plugin_copies(codex_home: Path, config: str) -> list[Path]:
    collisions: set[Path] = set()
    for plugin_id in _active_plugin_ids(config):
        name, separator, marketplace = plugin_id.partition("@")
        components = (name, marketplace) if separator else (name,)
        if any(
            not component
            or component in {".", ".."}
            or "/" in component
            or "\\" in component
            for component in components
        ):
            raise RuntimeError(f"Unsafe Codex plugin identifier: {plugin_id!r}")
        cache_parent = codex_home / "plugins" / "cache"
        cache_roots = (
            [cache_parent / marketplace / name]
            if separator
            else [entry / name for entry in cache_parent.iterdir() if entry.is_dir()]
            if cache_parent.is_dir()
            else []
        )
        for cache_root in cache_roots:
            for candidate in cache_root.glob(f"*/skills/{PRODUCT_UI_SKILL}/SKILL.md"):
                if candidate.is_file():
                    collisions.add(candidate)
        source_roots = {
            codex_home.parent / "plugins" / name,
            codex_home.parent / ".agents" / "plugins" / "plugins" / name,
        }
        if separator:
            source_roots.add(
                codex_home.parent
                / ".agents"
                / "plugins"
                / "marketplaces"
                / marketplace
                / "plugins"
                / name
            )
        for source_root in source_roots:
            source_candidate = (
                source_root / "skills" / PRODUCT_UI_SKILL / "SKILL.md"
            )
            if source_candidate.is_file():
                collisions.add(source_candidate)
    return sorted(collisions)


def _bounded_tree_entries(
    root: Path,
    *,
    label: str,
    maximum: int,
) -> list[tuple[Path, os.stat_result]]:
    _validate_existing_ancestry(root, label=label)
    root_metadata = os.lstat(root)
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeError(f"{label} root is not a real directory: {root}")
    discovered: list[tuple[Path, os.stat_result]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise RuntimeError(f"{label} changed during tree inspection: {root}") from exc
        child_directories: list[Path] = []
        for entry in children:
            candidate = Path(entry.path)
            try:
                # DirEntry.stat may return a cached result on Windows.  Bind
                # the later handle read to a fresh path observation instead.
                metadata = os.lstat(candidate)
            except OSError as exc:
                raise RuntimeError(
                    f"{label} changed during tree inspection: {root}"
                ) from exc
            if _is_link_or_reparse(metadata):
                raise RuntimeError(
                    f"Refusing linked or reparse-point entry in {label}: {candidate}"
                )
            discovered.append((candidate, metadata))
            if len(discovered) > maximum:
                raise RuntimeError(f"{label} exceeds the entry-count safety limit")
            if stat.S_ISDIR(metadata.st_mode):
                child_directories.append(candidate)
            elif not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"Unsupported entry in {label}: {candidate}")
        pending.extend(reversed(child_directories))
    return sorted(discovered, key=lambda item: item[0].relative_to(root).as_posix())


def _inspect_install_tree(
    target: Path,
    *,
    label: str,
    max_entries: int = MAX_INSTALL_TREE_ENTRIES,
    max_file_bytes: int = MAX_INSTALL_TREE_FILE_BYTES,
    max_total_bytes: int = MAX_INSTALL_TREE_TOTAL_BYTES,
    validate_windows_acl: bool = False,
) -> InstallTreeState:
    _validate_existing_ancestry(target, label=label)
    verify_windows_acl = validate_windows_acl and _windows_acl_required()
    try:
        root_before = os.lstat(target)
    except FileNotFoundError:
        return InstallTreeState(False, (), None)
    if _is_link_or_reparse(root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise InstallPreimageDrift(
            f"{label} target is not a real directory: {target}"
        )
    entries: list[
        tuple[str, str, bytes, tuple[int, int, int, int, int, int, int, int, int]]
    ] = []
    total_bytes = 0
    try:
        candidates = _bounded_tree_entries(
            target,
            label=label,
            maximum=max_entries,
        )
    except RuntimeError as exc:
        raise InstallPreimageDrift(str(exc)) from exc
    if verify_windows_acl:
        try:
            _ensure_windows_private_acls(
                [target, *(candidate for candidate, _metadata in candidates)],
                label=f"{label} tree",
            )
            root_acl_after = os.lstat(target)
        except (OSError, RuntimeError) as exc:
            raise InstallPreimageDrift(
                f"{label} has an unsafe Windows ACL: {exc}"
            ) from exc
        if (
            _is_link_or_reparse(root_acl_after)
            or not stat.S_ISDIR(root_acl_after.st_mode)
            or _stat_identity(root_before) != _stat_identity(root_acl_after)
        ):
            raise InstallPreimageDrift(
                f"{label} changed during Windows ACL validation: {target}"
            )
    for candidate, metadata in candidates:
        relative = candidate.relative_to(target).as_posix()
        if verify_windows_acl:
            try:
                refreshed = os.lstat(candidate)
            except OSError as exc:
                raise InstallPreimageDrift(
                    f"{label} changed during Windows ACL validation: {candidate}"
                ) from exc
            if (
                _is_link_or_reparse(refreshed)
                or stat.S_IFMT(metadata.st_mode) != stat.S_IFMT(refreshed.st_mode)
                or _stat_identity(metadata) != _stat_identity(refreshed)
            ):
                raise InstallPreimageDrift(
                    f"{label} changed during Windows ACL validation: {target}"
                )
            metadata = refreshed
        if stat.S_ISDIR(metadata.st_mode):
            entries.append((relative, "directory", b"", _stat_identity(metadata)))
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallPreimageDrift(f"Unsupported entry in {label}: {candidate}")
        try:
            raw, opened = _read_regular_file(
                candidate,
                label=f"{label} file",
                max_bytes=max_file_bytes,
            )
        except ManagedAgentsError as exc:
            raise InstallPreimageDrift(
                f"{label} changed during tree inspection: {target}"
            ) from exc
        if _stat_identity(metadata) != _stat_identity(opened):
            raise InstallPreimageDrift(
                f"{label} changed during tree inspection: {target}"
            )
        total_bytes += len(raw)
        if total_bytes > max_total_bytes:
            raise InstallPreimageDrift(f"{label} exceeds the aggregate byte safety limit")
        entries.append((relative, "file", raw, _stat_identity(opened)))
    root_after = os.lstat(target)
    if (
        _is_link_or_reparse(root_after)
        or not stat.S_ISDIR(root_after.st_mode)
        or _stat_identity(root_before) != _stat_identity(root_after)
    ):
        raise InstallPreimageDrift(f"{label} changed during tree inspection: {target}")
    return InstallTreeState(True, tuple(entries), _stat_identity(root_after))


def _inspect_product_ui_tree(
    target: Path,
    *,
    validate_windows_acl: bool = False,
) -> InstallTreeState:
    return _inspect_install_tree(
        target,
        label="Product UI skill",
        max_entries=MAX_PRODUCT_UI_SKILL_ENTRIES,
        max_file_bytes=MAX_PRODUCT_UI_SKILL_FILE_BYTES,
        max_total_bytes=MAX_PRODUCT_UI_SKILL_TOTAL_BYTES,
        validate_windows_acl=validate_windows_acl,
    )


def _install_tree_state_matches(
    target: Path,
    expected: InstallTreeState,
    *,
    label: str = "install tree",
) -> bool:
    try:
        return (
            _inspect_install_tree(
                target,
                label=label,
                validate_windows_acl=True,
            )
            == expected
        )
    except (OSError, RuntimeError):
        return False


def _product_ui_skill_state_is_owned(
    target: InstallTreeState,
    source: InstallTreeState,
) -> bool:
    if not target.exists:
        return False
    target_files = {
        relative: content
        for relative, kind, content, _identity in target.entries
        if kind == "file"
    }
    if target_files.get(PRODUCT_UI_OWNER_FILE) == PRODUCT_UI_OWNER_CONTENT.encode(
        "utf-8"
    ):
        return True
    source_files = {
        relative: content
        for relative, kind, content, _identity in source.entries
        if kind == "file"
    }
    return target_files == source_files


def _linux_renameat2_syscall_number() -> Optional[int]:
    machine = os.uname().machine.lower()
    return {
        "x86_64": 316,
        "amd64": 316,
        "i386": 353,
        "i486": 353,
        "i586": 353,
        "i686": 353,
        "arm": 382,
        "armv7l": 382,
        "aarch64": 276,
        "arm64": 276,
        "riscv64": 276,
        "loongarch64": 276,
        "ppc64": 357,
        "ppc64le": 357,
        "s390": 347,
        "s390x": 347,
    }.get(machine)


def _rename_path_noreplace(source: Path, target: Path) -> None:
    """Atomically rename a file or directory only when the destination is absent."""

    _validate_existing_ancestry(target, label="tree activation target")
    if os.name == "nt":
        # Windows rename already refuses any existing destination.
        os.rename(source, target)
        return
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(-100, source_bytes, -100, target_bytes, 1)
        else:
            syscall_number = _linux_renameat2_syscall_number()
            syscall = getattr(libc, "syscall", None)
            if syscall_number is None or syscall is None:
                raise OSError(
                    errno.ENOTSUP,
                    "atomic no-replace directory activation is unavailable",
                    os.fspath(target),
                )
            syscall.restype = ctypes.c_long
            result = syscall(
                syscall_number,
                -100,
                source_bytes,
                -100,
                target_bytes,
                1,
            )
    elif sys.platform == "darwin":
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace directory activation is unavailable",
                os.fspath(target),
            )
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(source_bytes, target_bytes, 0x00000004)
    else:
        raise OSError(
            errno.ENOTSUP,
            "atomic no-replace directory activation is unavailable",
            os.fspath(target),
        )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error, os.strerror(error), os.fspath(target))
        raise OSError(error, os.strerror(error), os.fspath(target))


def _rename_tree_noreplace(source: Path, target: Path) -> None:
    """Atomically rename a directory only when the destination is absent."""

    _rename_path_noreplace(source, target)


def _restore_or_retain_tree(
    displaced: Path,
    target: Path,
    retained: Optional[Path],
) -> bool:
    """Restore a displaced tree, or retain it when the target was recreated."""

    try:
        _rename_tree_noreplace(displaced, target)
        return False
    except (OSError, RuntimeError):
        if retained is None:
            return True
    assert retained is not None
    try:
        _rename_tree_noreplace(displaced, retained)
        return False
    except (OSError, RuntimeError):
        return True


def copytree_replace_cas(
    source: Path,
    target: Path,
    expected: InstallTreeState,
    *,
    retain_preimage: Optional[Path] = None,
    label: str = "Product UI skill",
) -> InstallTreeState:
    """Replace one installer-owned tree without erasing a raced user tree."""
    _validate_existing_ancestry(target, label=label)
    target.parent.mkdir(parents=True, exist_ok=True)
    _validate_existing_ancestry(target, label=label)
    staging = target.parent / f".{target.name}.jstack-stage-{uuid.uuid4().hex}"
    displaced = target.parent / f".{target.name}.jstack-displaced-{uuid.uuid4().hex}"
    moved = False
    installed = False
    try:
        _inspect_install_tree(source, label=f"staged {label}")
        shutil.copytree(
            source,
            staging,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
        )
        _inspect_install_tree(
            staging,
            label=f"activation copy for {label}",
            validate_windows_acl=True,
        )
        try:
            _rename_tree_noreplace(target, displaced)
            moved = True
        except FileNotFoundError:
            moved = False
        except (OSError, RuntimeError) as exc:
            raise InstallPreimageDrift(
                f"{label} could not be displaced safely: {target}"
            ) from exc
        except BaseException:
            destination_present = (
                displaced.exists() or _path_is_link_or_reparse(displaced)
            )
            moved = destination_present
            raise
        if moved:
            try:
                observed = _inspect_install_tree(
                    displaced,
                    label=label,
                    validate_windows_acl=True,
                )
            except (OSError, RuntimeError):
                observed = None
            if not expected.exists or observed != expected:
                moved = _restore_or_retain_tree(
                    displaced,
                    target,
                    retain_preimage,
                )
                raise InstallPreimageDrift(
                    f"{label} changed during atomic activation: {target}"
                )
        elif expected.exists:
            raise InstallPreimageDrift(
                f"{label} disappeared during atomic activation: {target}"
            )
        _rename_tree_noreplace(staging, target)
        installed = True
        postimage = _inspect_install_tree(
            target,
            label=label,
            validate_windows_acl=True,
        )
        if moved:
            if (
                _inspect_install_tree(
                    displaced,
                    label=label,
                    validate_windows_acl=True,
                )
                != expected
            ):
                if retain_preimage is not None:
                    try:
                        _rename_tree_noreplace(displaced, retain_preimage)
                        moved = False
                    except (OSError, RuntimeError):
                        pass
                raise InstallPreimageDrift(
                    f"{label} preimage changed during atomic activation; "
                    "the live target and recoverable preimage were preserved"
                )
            if retain_preimage is None:
                raise InstallPreimageDrift(
                    f"{label} needs a durable preimage retention path: {target}"
                )
            _rename_tree_noreplace(displaced, retain_preimage)
            moved = False
        return postimage
    except (OSError, RuntimeError) as exc:
        if moved and (
            displaced.exists() or _path_is_link_or_reparse(displaced)
        ):
            moved = _restore_or_retain_tree(
                displaced,
                target,
                retain_preimage,
            )
        raise InstallPreimageDrift(
            f"{label} changed during atomic activation: {target}"
        ) from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if moved and (displaced.exists() or _path_is_link_or_reparse(displaced)):
            _restore_or_retain_tree(
                displaced,
                target,
                retain_preimage,
            )
        if not installed and _path_is_link_or_reparse(target):
            # Never unlink a raced link/reparse point; the transaction will
            # preserve and report the conflict.
            pass


def copytree_replace(source: Path, target: Path) -> None:
    """Compatibility wrapper over the preimage-aware tree activator."""

    expected = _inspect_install_tree(target, label="install tree")
    retained = target.parent / f".{target.name}.jstack-rollback-{uuid.uuid4().hex}"
    completed = False
    try:
        copytree_replace_cas(
            source,
            target,
            expected,
            retain_preimage=retained,
            label="install tree",
        )
        completed = True
    finally:
        if completed and (retained.exists() or _path_is_link_or_reparse(retained)):
            remove_path(retained)


def atomic_write_text(
    path: Path,
    content: str,
    mode: int = 0o600,
) -> InstallFileState:
    _validate_existing_ancestry(path, label="staged installer file")
    if _path_is_link_or_reparse(path):
        raise RuntimeError(
            f"Refusing to write through linked or reparse-point path: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_existing_ancestry(path, label="staged installer file")
    temporary = path.parent / f".{path.name}.jstack-{uuid.uuid4().hex}"
    encoded = content.encode("utf-8")
    try:
        temporary.write_bytes(encoded)
        temporary.chmod(mode)
        temporary_stat = os.lstat(temporary)
        written_state = InstallFileState(
            True,
            encoded,
            _stat_identity(temporary_stat),
        )
        os.replace(temporary, path)
        return written_state
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_text_cas(
    path: Path,
    content: str,
    expected: InstallFileState,
    *,
    label: str,
    mode: int = 0o600,
    retain_preimage: Optional[Path] = None,
) -> InstallFileState:
    _validate_existing_ancestry(path, label=label)
    if _path_is_link_or_reparse(path):
        raise InstallPreimageDrift(
            f"Refusing to replace linked or reparse-point {label}: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_existing_ancestry(path, label=label)
    temporary = path.parent / f".{path.name}.jstack-{uuid.uuid4().hex}"
    encoded = content.encode("utf-8")
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:  # pragma: no cover
                raise RuntimeError(f"{label} write made no progress")
            offset += written
        _set_open_file_mode(descriptor, temporary, mode)
        _preserve_windows_file_acl(path, temporary)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        return _activate_staged_file_cas(
            temporary,
            path,
            expected,
            label=label,
            retain_preimage=retain_preimage,
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def archive_existing(path: Path, archive_root: Path) -> Optional[Path]:
    if not path.exists() and not _path_is_link_or_reparse(path):
        return None
    _validate_existing_ancestry(path, label="legacy archive source")
    if _path_is_link_or_reparse(path):
        raise RuntimeError(
            f"Refusing to archive linked or reparse-point install target: {path}"
        )
    _validate_existing_ancestry(archive_root, label="legacy archive root")
    archive_root.mkdir(parents=True, exist_ok=True)
    _validate_existing_ancestry(archive_root, label="legacy archive root")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    target = archive_root / f"{path.name}-{stamp}-{uuid.uuid4().hex[:8]}"
    metadata = os.lstat(path)
    if stat.S_ISREG(metadata.st_mode):
        _move_file_noreplace(path, target, label="legacy archive destination")
    elif stat.S_ISDIR(metadata.st_mode):
        _rename_tree_noreplace(path, target)
    else:
        raise RuntimeError(f"Unsupported legacy archive target: {path}")
    return target


def remove_path(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if _is_link_or_reparse(metadata):
        if stat.S_ISDIR(metadata.st_mode):
            os.rmdir(path)
        else:
            path.unlink()
    elif stat.S_ISREG(metadata.st_mode):
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


class InstallTransaction:
    """Stage a complete install and restore every target if any phase fails."""

    def __init__(self, codex_home: Path) -> None:
        token = uuid.uuid4().hex
        self.codex_home = _absolute_without_resolving(codex_home)
        self.root = self.codex_home / f".jstack-install-{token}"
        self.retained_root = (
            self.codex_home / "jstack-backups" / f"install-preimages-{token}"
        )
        self.stage_root = self.root / "stage"
        self.backup_root = self.root / "backup"
        _validate_existing_ancestry(self.root, label="install transaction")
        _validate_existing_ancestry(
            self.retained_root,
            label="retained installer preimages",
        )
        try:
            self.stage_root.mkdir(parents=True)
            self.backup_root.mkdir(parents=True)
            self.retained_root.mkdir(parents=True)
            if os.name == "posix":
                self.root.chmod(0o700)
                self.retained_root.chmod(0o700)
            _validate_existing_ancestry(self.root, label="install transaction")
            _validate_existing_ancestry(
                self.retained_root,
                label="retained installer preimages",
            )
            for managed_path in (
                self.root,
                self.stage_root,
                self.backup_root,
                self.retained_root.parent,
                self.retained_root,
            ):
                _validate_windows_managed_path(
                    self.codex_home,
                    managed_path,
                    label="installer transaction path",
                )
            retained_metadata = os.lstat(self.retained_root)
            if _is_link_or_reparse(retained_metadata) or not stat.S_ISDIR(
                retained_metadata.st_mode
            ):
                raise RuntimeError(
                    "Retained installer preimages require a real directory."
                )
            _ensure_windows_private_acl(
                self.retained_root,
                label="retained installer preimages",
            )
        except BaseException:
            shutil.rmtree(self.root, ignore_errors=True)
            if self.retained_root.exists() and not _path_is_link_or_reparse(
                self.retained_root
            ):
                shutil.rmtree(self.retained_root, ignore_errors=True)
            try:
                self.retained_root.parent.rmdir()
            except OSError:
                pass
            raise
        self.snapshots: list[tuple[Path, Optional[Path]]] = []
        self.archives: list[tuple[Path, Path, str, Any]] = []
        self.rollback_expectations: dict[Path, InstallFileState] = {}
        self.rollback_tree_expectations: dict[Path, InstallTreeState] = {}
        self.rollback_file_preimages: dict[Path, InstallFileState] = {}
        self.rollback_tree_preimages: dict[Path, InstallTreeState] = {}
        self.rollback_mutated_targets: set[Path] = set()
        self.rollback_preimages: dict[Path, Path] = {}
        self.rollback_preserve_targets: set[Path] = set()
        self.pending_file_mutations: dict[
            Path, tuple[InstallFileState, Path, bytes, int]
        ] = {}
        self.pending_tree_mutations: dict[
            Path, tuple[InstallTreeState, Path, InstallTreeState]
        ] = {}
        self.retained_count = 0
        self.retained_paths: list[Path] = []
        self.initial_missing_dirs: set[Path] = set()

    def retain_path(self, label: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") or "target"
        path = self.retained_root / f"{self.retained_count:04d}-{safe}"
        self.retained_count += 1
        _validate_existing_ancestry(path, label="retained installer preimage")
        _validate_windows_managed_path(
            self.codex_home,
            path,
            label="retained installer preimage",
        )
        self.retained_paths.append(path)
        return path

    def stage_tree(self, name: str, source: Path) -> Path:
        target = self.stage_root / name
        _inspect_install_tree(source, label=f"installer source tree {name}")
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
        )
        _inspect_install_tree(target, label=f"staged installer tree {name}")
        _validate_windows_managed_path(
            self.codex_home,
            target,
            label=f"staged installer tree {name}",
        )
        return target

    def snapshot(self, target: Path, *, preserve_owner: bool = False) -> None:
        """Journal a target without copying attacker-controlled filesystem objects.

        The bounded preflight states are recorded by the caller and the exact
        original object is atomically retained when activation begins.  A raw
        copy here was redundant and could block on or recursively copy a target
        raced to a FIFO or oversized tree.
        """

        del preserve_owner
        parent = target.parent
        while parent != self.root.parent and self.root.parent in parent.parents:
            if not parent.exists():
                self.initial_missing_dirs.add(parent)
            parent = parent.parent
        _validate_existing_ancestry(target, label="install target")
        _validate_windows_managed_path(
            self.codex_home,
            target,
            label="install target",
        )
        if _path_is_link_or_reparse(target):
            raise RuntimeError(
                f"Refusing to replace linked or reparse-point install target: {target}"
            )
        try:
            target_metadata = os.lstat(target)
        except FileNotFoundError:
            target_metadata = None
        if target_metadata is not None:
            if _is_link_or_reparse(target_metadata):
                raise RuntimeError(
                    f"Refusing to snapshot linked or reparse-point install target: {target}"
                )
            if not (
                stat.S_ISDIR(target_metadata.st_mode)
                or stat.S_ISREG(target_metadata.st_mode)
            ):
                raise RuntimeError(f"Unsupported install target: {target}")
        self.snapshots.append((target, None))

    def expect_rollback_state(
        self,
        target: Path,
        state: InstallFileState,
        *,
        retained_preimage: Optional[Path] = None,
    ) -> None:
        """Restore a file only while it remains in the installer-expected state."""

        self.rollback_expectations[target] = state
        self.pending_file_mutations.pop(target, None)
        if retained_preimage is not None:
            self.rollback_mutated_targets.add(target)
            self.rollback_preimages[target] = retained_preimage
        else:
            self.rollback_file_preimages[target] = state

    def expect_rollback_tree_state(
        self,
        target: Path,
        state: InstallTreeState,
        *,
        retained_preimage: Optional[Path] = None,
    ) -> None:
        self.rollback_tree_expectations[target] = state
        self.pending_tree_mutations.pop(target, None)
        if retained_preimage is not None:
            self.rollback_mutated_targets.add(target)
            self.rollback_preimages[target] = retained_preimage
        else:
            self.rollback_tree_preimages[target] = state

    def preserve_on_rollback(self, target: Path) -> None:
        self.rollback_preserve_targets.add(target)

    def prepare_file_mutation(
        self,
        target: Path,
        original: InstallFileState,
        retained: Path,
        content: str,
        mode: int,
    ) -> None:
        """Journal enough intent to recover an interrupt after atomic activation."""

        self.pending_file_mutations[target] = (
            original,
            retained,
            content.encode("utf-8"),
            mode,
        )

    def prepare_tree_mutation(
        self,
        target: Path,
        original: InstallTreeState,
        retained: Path,
        source: Path,
        *,
        label: str,
    ) -> None:
        self.pending_tree_mutations[target] = (
            original,
            retained,
            _inspect_install_tree(source, label=f"staged {label}"),
        )

    @staticmethod
    def _tree_payload(state: InstallTreeState) -> tuple[Any, ...]:
        root_mode = (
            stat.S_IMODE(state.stat_identity[2])
            if state.stat_identity is not None
            else None
        )
        entries = tuple(
            (relative, kind, content, stat.S_IMODE(identity[2]))
            for relative, kind, content, identity in state.entries
        )
        return state.exists, root_mode, entries

    def _reconcile_interrupted_mutations(self) -> None:
        for target, (original, retained, content, mode) in list(
            self.pending_file_mutations.items()
        ):
            if target in self.rollback_preserve_targets:
                continue
            try:
                current = _inspect_install_file(
                    target,
                    label="interrupted installer target",
                )
            except (OSError, RuntimeError):
                self.preserve_on_rollback(target)
                continue
            retained_matches = (
                _install_file_state_matches(retained, original)
                if original.exists
                else not retained.exists() and not _path_is_link_or_reparse(retained)
            )
            mode_matches = bool(
                current.stat_identity is not None
                and (
                    os.name != "posix"
                    or stat.S_IMODE(current.stat_identity[2]) == mode
                )
            )
            if current.exists and current.content == content and mode_matches and retained_matches:
                self.expect_rollback_state(
                    target,
                    current,
                    retained_preimage=retained,
                )
            elif (
                current == original
                and not retained.exists()
                and not _path_is_link_or_reparse(retained)
            ):
                self.pending_file_mutations.pop(target, None)
            else:
                self.preserve_on_rollback(target)

        for target, (original, retained, intended) in list(
            self.pending_tree_mutations.items()
        ):
            if target in self.rollback_preserve_targets:
                continue
            try:
                current = _inspect_install_tree(
                    target,
                    label="interrupted installer tree",
                )
            except (OSError, RuntimeError):
                self.preserve_on_rollback(target)
                continue
            retained_matches = (
                _install_tree_state_matches(retained, original)
                if original.exists
                else not retained.exists() and not _path_is_link_or_reparse(retained)
            )
            if (
                self._tree_payload(current) == self._tree_payload(intended)
                and retained_matches
            ):
                self.expect_rollback_tree_state(
                    target,
                    current,
                    retained_preimage=retained,
                )
            elif (
                current == original
                and not retained.exists()
                and not _path_is_link_or_reparse(retained)
            ):
                self.pending_tree_mutations.pop(target, None)
            else:
                self.preserve_on_rollback(target)

    def _discard_retained_preimages(self) -> None:
        try:
            self.retained_root.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            return
        retained_parent = self.retained_root.parent
        try:
            retained_parent.rmdir()
        except OSError:
            pass

    def archive(self, source: Path, archive_root: Path) -> Optional[Path]:
        if not source.exists() and not _path_is_link_or_reparse(source):
            return None
        _validate_existing_ancestry(source, label="archive source")
        _validate_windows_managed_path(
            self.codex_home,
            source,
            label="legacy archive source",
        )
        if _path_is_link_or_reparse(source):
            raise RuntimeError(
                f"Refusing to archive linked or reparse-point install target: {source}"
            )
        source_metadata = os.lstat(source)
        if stat.S_ISDIR(source_metadata.st_mode):
            kind = "tree"
            preimage: Any = _inspect_install_tree(
                source,
                label="legacy archive tree",
                validate_windows_acl=True,
            )
        elif stat.S_ISREG(source_metadata.st_mode):
            kind = "file"
            preimage = _inspect_install_file(
                source,
                label="legacy archive file",
            )
        else:
            raise RuntimeError(f"Unsupported legacy archive target: {source}")
        _validate_existing_ancestry(archive_root, label="legacy archive root")
        archive_root.mkdir(parents=True, exist_ok=True)
        _validate_existing_ancestry(archive_root, label="legacy archive root")
        _validate_windows_managed_path(
            self.codex_home,
            archive_root,
            label="legacy archive root",
        )
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        target = archive_root / f"{source.name}-{stamp}-{uuid.uuid4().hex[:8]}"
        _validate_existing_ancestry(target, label="legacy archive destination")
        if target.exists() or _path_is_link_or_reparse(target):
            raise InstallPreimageDrift(
                f"Legacy archive destination unexpectedly exists: {target}"
            )
        try:
            if kind == "tree":
                _rename_tree_noreplace(source, target)
            else:
                _move_file_noreplace(
                    source,
                    target,
                    label="legacy archive destination",
                )
        except BaseException:
            # A KeyboardInterrupt can arrive after the atomic move returns from
            # the kernel but before the next Python statement.  Recover the
            # journal from the exact destination rather than orphaning it.
            try:
                moved_state = (
                    _inspect_install_tree(
                        target,
                        label="legacy archive tree",
                        validate_windows_acl=True,
                    )
                    if kind == "tree"
                    else _inspect_install_file(target, label="legacy archive file")
                )
            except (OSError, RuntimeError):
                moved_state = None
            source_absent = (
                not source.exists() and not _path_is_link_or_reparse(source)
            )
            if source_absent or moved_state == preimage:
                self.archives.append((source, target, kind, preimage))
            raise
        # Journal immediately after the atomic move.  If inspection below
        # fails, outer rollback can restore the object without overwriting a
        # concurrently recreated source, or retain it at this durable archive.
        self.archives.append((source, target, kind, preimage))
        try:
            observed = (
                _inspect_install_tree(
                    target,
                    label="legacy archive tree",
                    validate_windows_acl=True,
                )
                if kind == "tree"
                else _inspect_install_file(target, label="legacy archive file")
            )
        except (OSError, RuntimeError) as exc:
            raise InstallPreimageDrift(
                f"Legacy archive target changed during activation: {source}"
            ) from exc
        if (
            observed != preimage
            or source.exists()
            or _path_is_link_or_reparse(source)
        ):
            raise InstallPreimageDrift(
                f"Legacy archive target changed during activation: {source}; "
                "the source and durable archive were preserved"
            )
        return target

    def rollback(self) -> None:
        errors: list[str] = []
        preserve_transaction_root = False
        rollback_retained_postimages = False
        try:
            self._reconcile_interrupted_mutations()
        except Exception as exc:  # pragma: no cover - catastrophic filesystem failure
            errors.append(f"interrupted mutation journal: {exc}")
            preserve_transaction_root = True
        for source, archived, kind, preimage in reversed(self.archives):
            try:
                if source.exists() or _path_is_link_or_reparse(source):
                    errors.append(
                        f"preserved concurrent change instead of restoring archived {source}"
                    )
                    continue
                observed = (
                    _inspect_install_tree(
                        archived,
                        label="legacy archive tree",
                        validate_windows_acl=True,
                    )
                    if kind == "tree"
                    else _inspect_install_file(archived, label="legacy archive file")
                )
                if observed != preimage:
                    errors.append(
                        f"preserved changed archive instead of restoring {source}"
                    )
                    continue
                source.parent.mkdir(parents=True, exist_ok=True)
                if kind == "file":
                    _move_file_noreplace(
                        archived,
                        source,
                        label="restored legacy archive file",
                    )
                    restored = _inspect_install_file(
                        source,
                        label="restored legacy archive file",
                    )
                else:
                    _rename_tree_noreplace(archived, source)
                    restored = _inspect_install_tree(
                        source,
                        label="restored legacy archive tree",
                        validate_windows_acl=True,
                    )
                if restored != preimage:
                    errors.append(f"legacy archive restore drifted for {source}")
            except Exception as exc:  # pragma: no cover - catastrophic filesystem failure
                errors.append(f"archive restore {source}: {exc}")
        for target, _backup in reversed(self.snapshots):
            try:
                if target in self.rollback_preserve_targets:
                    errors.append(
                        f"preserved concurrent change instead of restoring {target}"
                    )
                    continue
                expected = self.rollback_expectations.get(target)
                expected_tree = self.rollback_tree_expectations.get(target)
                if target not in self.rollback_mutated_targets:
                    unchanged = (
                        _install_file_state_matches(target, expected)
                        if expected is not None
                        else _install_tree_state_matches(target, expected_tree)
                        if expected_tree is not None
                        else True
                    )
                    if not unchanged:
                        errors.append(
                            f"preserved concurrent change instead of restoring {target}"
                        )
                    continue
                retained = self.rollback_preimages.get(target)
                original_file = self.rollback_file_preimages.get(target)
                original_tree = self.rollback_tree_preimages.get(target)
                kind = "file" if expected is not None else "tree"
                if expected is None and expected_tree is None:
                    errors.append(f"rollback state is unavailable for {target}")
                    continue
                original_exists = bool(
                    (original_file is not None and original_file.exists)
                    or (original_tree is not None and original_tree.exists)
                )
                retained_exists = bool(
                    retained is not None
                    and (retained.exists() or _path_is_link_or_reparse(retained))
                )
                retained_matches = (
                    retained is not None
                    and not _path_is_link_or_reparse(retained)
                    and (
                        _install_file_state_matches(retained, original_file)
                        if original_file is not None
                        else _install_tree_state_matches(retained, original_tree)
                        if original_tree is not None
                        else False
                    )
                )
                if (
                    retained is None
                    or retained_exists != original_exists
                    or (original_exists and not retained_matches)
                ):
                    errors.append(
                        f"exact retained preimage is unavailable for {target}"
                    )
                    continue
                quarantine = self.backup_root / (
                    f"rollback-current-{uuid.uuid4().hex}-{target.name}"
                )
                try:
                    if kind == "file":
                        _move_file_noreplace(
                            target,
                            quarantine,
                            label="rollback quarantine",
                        )
                        observed_current: Any = _inspect_install_file(
                            quarantine,
                            label="rollback quarantine",
                        )
                    else:
                        _rename_tree_noreplace(target, quarantine)
                        observed_current = _inspect_install_tree(
                            quarantine,
                            label="rollback quarantine",
                        )
                except (OSError, RuntimeError) as exc:
                    if quarantine.exists() or _path_is_link_or_reparse(quarantine):
                        recovery = self.retain_path(
                            f"rollback-uninspected-{target.name}"
                        )
                        stuck = (
                            _restore_or_retain_file(
                                quarantine,
                                target,
                                recovery,
                                label="rollback target",
                            )
                            if kind == "file"
                            else _restore_or_retain_tree(
                                quarantine,
                                target,
                                recovery,
                            )
                        )
                        preserve_transaction_root = preserve_transaction_root or stuck
                    errors.append(
                        f"preserved concurrent change instead of restoring {target}: {exc}"
                    )
                    continue

                expected_current: Any = expected if kind == "file" else expected_tree
                if observed_current != expected_current:
                    recovery = self.retain_path(f"rollback-conflict-{target.name}")
                    stuck = (
                        _restore_or_retain_file(
                            quarantine,
                            target,
                            recovery,
                            label="rollback target",
                        )
                        if kind == "file"
                        else _restore_or_retain_tree(
                            quarantine,
                            target,
                            recovery,
                        )
                    )
                    preserve_transaction_root = preserve_transaction_root or stuck
                    errors.append(
                        f"preserved concurrent change instead of restoring {target}"
                    )
                    continue

                restore_failed: Optional[Exception] = None
                if original_exists:
                    assert retained is not None
                    target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        if kind == "file":
                            _move_file_noreplace(
                                retained,
                                target,
                                label="rollback target",
                            )
                        else:
                            _rename_tree_noreplace(retained, target)
                    except (OSError, RuntimeError) as exc:
                        restore_failed = exc

                restored_matches = (
                    _install_file_state_matches(target, original_file)
                    if original_file is not None
                    else _install_tree_state_matches(target, original_tree)
                    if original_tree is not None
                    else not target.exists() and not _path_is_link_or_reparse(target)
                )
                if restore_failed is not None or not restored_matches:
                    errors.append(
                        f"preserved concurrent change and exact retained preimage "
                        f"instead of restoring {target}"
                    )

                quarantine_unchanged = (
                    _install_file_state_matches(quarantine, expected)
                    if expected is not None
                    else _install_tree_state_matches(quarantine, expected_tree)
                    if expected_tree is not None
                    else False
                )
                if quarantine_unchanged:
                    recovery = self.retain_path(
                        f"rollback-postimage-{target.name}"
                    )
                    try:
                        if kind == "file":
                            _move_file_noreplace(
                                quarantine,
                                recovery,
                                label="retained rollback postimage",
                            )
                        else:
                            _rename_tree_noreplace(quarantine, recovery)
                        rollback_retained_postimages = True
                    except (OSError, RuntimeError) as exc:
                        preserve_transaction_root = True
                        errors.append(
                            f"could not retain rollback postimage for {target}: {exc}"
                        )
                else:
                    recovery = self.retain_path(
                        f"rollback-postimage-conflict-{target.name}"
                    )
                    try:
                        if kind == "file":
                            _move_file_noreplace(
                                quarantine,
                                recovery,
                                label="retained rollback conflict",
                            )
                        else:
                            _rename_tree_noreplace(quarantine, recovery)
                    except (OSError, RuntimeError):
                        preserve_transaction_root = True
                    errors.append(
                        f"preserved changed rollback quarantine for {target}"
                    )
            except Exception as exc:  # pragma: no cover - catastrophic filesystem failure
                errors.append(f"target restore {target}: {exc}")
                preserve_transaction_root = True
        if not preserve_transaction_root:
            shutil.rmtree(self.root, ignore_errors=True)
        for directory in sorted(
            self.initial_missing_dirs,
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
        retained_has_recovery = True
        try:
            retained_has_recovery = any(self.retained_root.iterdir())
        except FileNotFoundError:
            retained_has_recovery = False
        except OSError:
            pass
        if (
            (not errors and not rollback_retained_postimages)
            or not retained_has_recovery
        ):
            self._discard_retained_preimages()
        if errors:
            raise RuntimeError("JStack install rollback was incomplete: " + "; ".join(errors))

    def commit(self) -> None:
        errors: list[str] = []
        associated = set(self.rollback_preimages.values())
        for target, retained in self.rollback_preimages.items():
            original_file = self.rollback_file_preimages.get(target)
            original_tree = self.rollback_tree_preimages.get(target)
            original_exists = bool(
                (original_file is not None and original_file.exists)
                or (original_tree is not None and original_tree.exists)
            )
            if not original_exists:
                if retained.exists() or _path_is_link_or_reparse(retained):
                    errors.append(
                        f"unexpected retained preimage was preserved for {target}"
                    )
                continue
            retained_matches = (
                _install_file_state_matches(retained, original_file)
                if original_file is not None
                else _install_tree_state_matches(retained, original_tree)
                if original_tree is not None
                else False
            )
            if not retained_matches:
                errors.append(f"changed retained preimage was preserved for {target}")

        for retained in self.retained_paths:
            if retained not in associated and (
                retained.exists() or _path_is_link_or_reparse(retained)
            ):
                errors.append(f"unclassified retained installer object was preserved: {retained}")
        try:
            actual_children = set(self.retained_root.iterdir())
        except FileNotFoundError:
            actual_children = set()
        except OSError as exc:
            actual_children = set()
            errors.append(f"could not inspect retained recovery root: {exc}")
        unexpected_children = actual_children - associated
        if unexpected_children:
            errors.append(
                "unclassified retained installer objects were preserved: "
                + ", ".join(str(path) for path in sorted(unexpected_children))
            )

        if errors:
            shutil.rmtree(self.root, ignore_errors=True)
            raise InstallPreimageDrift(
                "JStack install committed with retained recovery objects: "
                + "; ".join(errors)
            )

        if actual_children:
            latest = self.retained_root.parent / "install-preimages-latest"
            try:
                if latest.exists() or _path_is_link_or_reparse(latest):
                    raise InstallPreimageDrift(
                        "The previous successful-install recovery still exists; "
                        "JStack will not delete it automatically"
                    )
                _rename_tree_noreplace(self.retained_root, latest)
            except (OSError, RuntimeError) as exc:
                shutil.rmtree(self.root, ignore_errors=True)
                raise InstallPreimageDrift(
                    "JStack installed, but recovery retention failed safely; "
                    "all recovery objects were preserved"
                ) from exc
        else:
            self._discard_retained_preimages()

        shutil.rmtree(self.root, ignore_errors=True)


def remove_existing_stack_blocks(config: str) -> str:
    if any(
        delimiter in _toml_without_comment(line)
        for line in config.splitlines()
        for delimiter in ('"""', "'''")
    ):
        raise RuntimeError(
            "Refusing to rewrite a Codex config.toml containing multiline strings"
        )
    if _tomllib is not None:
        try:
            parsed = _tomllib.loads(config)
        except Exception as exc:
            raise RuntimeError("Unable to parse Codex config.toml safely") from exc
        servers = parsed.get("mcp_servers", {})
        if not isinstance(servers, dict):
            raise RuntimeError("Codex config.toml mcp_servers value must be a table")
    lines = config.splitlines(keepends=True)
    output: list[str] = []
    current_table: tuple[str, ...] = ()
    skip_server: Optional[str] = None
    skip_array_depth = 0
    skip_value_depth = 0
    preserve_value_depth = 0
    seen_server_tables: set[str] = set()
    for line in lines:
        semantic = _toml_without_comment(line).strip()
        if not semantic:
            if skip_server is None and not skip_value_depth:
                output.append(line)
            continue
        if skip_value_depth:
            skip_value_depth += _toml_square_bracket_delta(semantic)
            if skip_value_depth < 0:
                raise RuntimeError("Unable to parse Codex MCP multiline array")
            continue
        if skip_server is not None and skip_array_depth:
            skip_array_depth += _toml_square_bracket_delta(semantic)
            if skip_array_depth < 0:
                raise RuntimeError("Unable to parse Codex MCP multiline array")
            continue
        if preserve_value_depth:
            preserve_value_depth += _toml_square_bracket_delta(semantic)
            if preserve_value_depth < 0:
                raise RuntimeError("Unable to parse Codex MCP multiline array")
            output.append(line)
            continue
        if semantic.startswith("[[") and semantic.endswith("]]" ):
            header = semantic[2:-2]
            try:
                parts = _toml_key_parts(header)
            except ValueError as exc:
                if "mcp_servers" in header:
                    raise RuntimeError("Unable to parse Codex MCP configuration") from exc
                parts = ()
            if parts and parts[0] == "mcp_servers":
                raise RuntimeError("Codex MCP configuration may not use array tables")
            current_table = parts
            skip_server = None
            skip_array_depth = 0
            output.append(line)
            continue
        if semantic.startswith("[") and semantic.endswith("]"):
            header = semantic[1:-1]
            try:
                current_table = _toml_key_parts(header)
            except ValueError as exc:
                if "mcp_servers" in header:
                    raise RuntimeError("Unable to parse Codex MCP configuration") from exc
                current_table = ()
            if (
                len(current_table) >= 2
                and current_table[0] == "mcp_servers"
                and current_table[1] in {"jstack", "gstack"}
            ):
                server_id = current_table[1]
                if len(current_table) == 2:
                    if server_id in seen_server_tables:
                        raise RuntimeError(
                            f"Codex MCP server {server_id} is declared more than once"
                        )
                    seen_server_tables.add(server_id)
                skip_server = server_id
                skip_array_depth = 0
                continue
            skip_server = None
            skip_array_depth = 0
            output.append(line)
            continue
        if skip_server is not None:
            try:
                _, raw_value = _split_toml_assignment(semantic)
            except ValueError:
                raw_value = ""
            skip_array_depth = _toml_square_bracket_delta(raw_value)
            if skip_array_depth < 0:
                raise RuntimeError("Unable to parse Codex MCP multiline array")
            continue
        try:
            raw_key, raw_value = _split_toml_assignment(_toml_without_comment(line))
            key = _toml_key_parts(raw_key)
        except ValueError:
            output.append(line)
            continue
        full_key = current_table + key
        if full_key == ("mcp_servers",):
            raise RuntimeError(
                "A root inline mcp_servers table cannot be updated safely"
            )
        if (
            len(full_key) >= 2
            and full_key[0] == "mcp_servers"
            and full_key[1] in {"jstack", "gstack"}
        ):
            skip_value_depth = _toml_square_bracket_delta(raw_value)
            if skip_value_depth < 0:
                raise RuntimeError("Unable to parse Codex MCP multiline array")
            continue
        preserve_value_depth = _toml_square_bracket_delta(raw_value)
        if preserve_value_depth < 0:
            raise RuntimeError("Unable to parse Codex MCP multiline array")
        output.append(line)
    if skip_array_depth or skip_value_depth or preserve_value_depth:
        raise RuntimeError("Unable to parse Codex MCP unterminated multiline array")
    rendered = "".join(output)
    if _tomllib is not None:
        try:
            _tomllib.loads(rendered)
        except Exception as exc:
            raise RuntimeError("Updated Codex config.toml would be invalid") from exc
    else:
        _active_plugin_ids_fallback(rendered)
    return rendered


def mcp_block(install_dir: Path) -> str:
    command = Path(sys.executable).as_posix()
    server = (install_dir / "jstack_mcp_server.py").as_posix()
    try:
        command_toml = json.dumps(command, ensure_ascii=False).replace(
            "\x7f",
            "\\u007F",
        )
        server_toml = json.dumps(server, ensure_ascii=False).replace(
            "\x7f",
            "\\u007F",
        )
        command_toml.encode("utf-8")
        server_toml.encode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError(
            "Python and CODEX_HOME paths must contain valid Unicode for TOML"
        ) from exc
    return f"""
[mcp_servers.jstack]
command = {command_toml}
args = [{server_toml}]
startup_timeout_sec = 30.0
tool_timeout_sec = 1900.0
""".strip()


def install(
    repo_root: Path,
    codex_home: Path,
    *,
    manage_agents: bool = False,
) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve()
    codex_home_input = _absolute_without_resolving(codex_home)
    if not repo_root.exists():
        raise RuntimeError(f"Repo root not found: {repo_root}")
    _validate_existing_ancestry(codex_home_input, label="Codex home")
    _validate_windows_install_root(codex_home_input)

    # Keep the validated lexical root.  Resolving it in a separate syscall
    # would follow an ancestor swapped to a symlink/junction after preflight.
    codex_home = codex_home_input

    prompts_dir = codex_home / "prompts"
    skills_root = codex_home / "skills"
    skill_dir = skills_root / "jstack-dev"
    audit_skill_dir = skills_root / "jstack-audit"
    loop_skill_dir = skills_root / "jstack-loop"
    product_ui_skill_dir = skills_root / PRODUCT_UI_SKILL
    mcp_root = codex_home / "mcp"
    mcp_dir = mcp_root / "jstack"
    config_path = codex_home / "config.toml"
    backup = config_path.with_suffix(".toml.jstack-backup")
    product_ui_source = repo_root / "skills" / PRODUCT_UI_SKILL

    managed_paths = [
        prompts_dir,
        *(prompts_dir / prompt for prompt in PROMPTS),
        prompts_dir / "gstack-dev.md",
        codex_home / "prompts-disabled",
        skills_root,
        skill_dir,
        audit_skill_dir,
        loop_skill_dir,
        product_ui_skill_dir,
        skills_root / "gstack-dev",
        codex_home / "skills-disabled",
        mcp_root,
        mcp_dir,
        config_path,
        backup,
        codex_home / "jstack-backups",
    ]
    if manage_agents:
        managed_paths.append(codex_home / "AGENTS.md")
    for managed_path in managed_paths:
        _validate_windows_managed_path(
            codex_home,
            managed_path,
            label="JStack managed path",
        )

    latest_recovery = codex_home / "jstack-backups" / "install-preimages-latest"
    if latest_recovery.exists() or _path_is_link_or_reparse(latest_recovery):
        raise RuntimeError(
            "A prior successful-install recovery exists at "
            f"{latest_recovery}. Verify and archive or remove it explicitly before "
            "another upgrade; JStack never deletes recovery data automatically."
        )

    agents_preimage = (
        inspect_managed_agents(codex_home / "AGENTS.md") if manage_agents else None
    )

    config_preimage = _inspect_install_file(config_path, label="Codex config.toml")
    try:
        original = config_preimage.content.decode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError(f"Codex config.toml is not valid UTF-8: {config_path}") from exc
    active_plugin_ids = _active_plugin_ids(original)
    known_plugin_owners = sorted(
        plugin_id
        for plugin_id in active_plugin_ids
        if plugin_id.partition("@")[0] in KNOWN_PRODUCT_UI_PLUGIN_NAMES
    )
    if known_plugin_owners:
        raise RuntimeError(
            "Refusing direct install because an enabled plugin owns "
            f"{PRODUCT_UI_SKILL}: {', '.join(known_plugin_owners)}"
        )
    active_copies = active_product_ui_plugin_copies(codex_home, original)
    if active_copies:
        rendered = ", ".join(str(path) for path in active_copies)
        raise RuntimeError(
            "Refusing direct install because an enabled plugin "
            f"already exposes {PRODUCT_UI_SKILL}: {rendered}"
        )
    try:
        product_ui_preimage = _inspect_product_ui_tree(
            product_ui_skill_dir,
            validate_windows_acl=True,
        )
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(
            "Refusing to replace an existing product-ui-design skill without "
            f"JStack ownership that can be verified: {product_ui_skill_dir}"
        ) from exc
    if product_ui_preimage.exists:
        product_ui_source_state = _inspect_product_ui_tree(product_ui_source)
        if not _product_ui_skill_state_is_owned(
            product_ui_preimage,
            product_ui_source_state,
        ):
            raise RuntimeError(
                "Refusing to replace an existing product-ui-design skill without "
                f"JStack ownership: {product_ui_skill_dir}"
            )
    prompt_preimages = {
        prompt: _inspect_install_file(
            prompts_dir / prompt,
            label=f"Codex prompt {prompt}",
        )
        for prompt in PROMPTS
    }
    skill_preimage = _inspect_install_tree(
        skill_dir,
        label="jstack-dev skill",
        validate_windows_acl=True,
    )
    audit_skill_preimage = _inspect_install_tree(
        audit_skill_dir,
        label="jstack-audit skill",
        validate_windows_acl=True,
    )
    loop_skill_preimage = _inspect_install_tree(
        loop_skill_dir,
        label="jstack-loop skill",
        validate_windows_acl=True,
    )
    mcp_preimage = _inspect_install_tree(
        mcp_dir,
        label="JStack MCP tree",
        validate_windows_acl=True,
    )

    prompt_contents = {
        prompt: (repo_root / "prompts" / prompt).read_text(encoding="utf-8")
        for prompt in PROMPTS
    }
    backup_preimage = _inspect_install_file(
        backup, label="Codex JStack config backup"
    )
    updated = remove_existing_stack_blocks(original)
    updated = updated.rstrip() + "\n\n" + mcp_block(mcp_dir) + "\n"
    if _tomllib is not None:
        try:
            _tomllib.loads(updated)
        except Exception as exc:
            raise RuntimeError("Updated Codex config.toml would be invalid") from exc
    else:
        _active_plugin_ids_fallback(updated)

    transaction = InstallTransaction(codex_home)
    try:
        staged_skill = transaction.stage_tree(
            "jstack-dev-skill",
            repo_root / "skills" / "jstack-dev",
        )
        staged_audit_skill = transaction.stage_tree(
            "jstack-audit-skill",
            repo_root / "skills" / "jstack-audit",
        )
        staged_loop_skill = transaction.stage_tree(
            "jstack-loop-skill",
            repo_root / "skills" / "jstack-loop",
        )
        staged_product_ui_skill = transaction.stage_tree(
            "product-ui-design-skill",
            product_ui_source,
        )
        atomic_write_text(
            staged_product_ui_skill / PRODUCT_UI_OWNER_FILE,
            PRODUCT_UI_OWNER_CONTENT,
            mode=0o644,
        )
        staged_mcp = transaction.stage_tree(
            "jstack-mcp",
            repo_root / "mcp" / "jstack",
        )
        staged_mastery = staged_mcp / "mastery"
        remove_path(staged_mastery)
        _inspect_install_tree(repo_root / "mastery", label="mastery source tree")
        shutil.copytree(repo_root / "mastery", staged_mastery)
        _inspect_install_tree(staged_mastery, label="staged mastery tree")
    except BaseException:
        transaction.rollback()
        raise

    install_targets = [
        *(prompts_dir / prompt for prompt in PROMPTS),
        skill_dir,
        audit_skill_dir,
        loop_skill_dir,
        product_ui_skill_dir,
        mcp_dir,
        backup,
        config_path,
    ]
    if agents_preimage is not None:
        install_targets.append(agents_preimage.path)
    file_preimages = {
        prompts_dir / prompt: preimage
        for prompt, preimage in prompt_preimages.items()
    }
    file_preimages[backup] = backup_preimage
    file_preimages[config_path] = config_preimage
    if agents_preimage is not None:
        file_preimages[agents_preimage.path] = InstallFileState(
            agents_preimage.exists,
            agents_preimage.content,
            agents_preimage.stat_identity,
        )
    tree_preimages = {
        skill_dir: skill_preimage,
        audit_skill_dir: audit_skill_preimage,
        loop_skill_dir: loop_skill_preimage,
        product_ui_skill_dir: product_ui_preimage,
        mcp_dir: mcp_preimage,
    }
    archived_prompt = None
    archived_skill = None
    try:
        for target in install_targets:
            transaction.snapshot(
                target,
                preserve_owner=agents_preimage is not None and target == agents_preimage.path,
            )
            if target in file_preimages:
                transaction.expect_rollback_state(target, file_preimages[target])
            if target in tree_preimages:
                transaction.expect_rollback_tree_state(target, tree_preimages[target])
    except BaseException:
        transaction.rollback()
        raise

    try:
        archived_prompt = transaction.archive(
            prompts_dir / "gstack-dev.md", codex_home / "prompts-disabled"
        )
        archived_skill = transaction.archive(
            skills_root / "gstack-dev", codex_home / "skills-disabled"
        )
        for prompt in PROMPTS:
            target = prompts_dir / prompt
            retained_prompt = transaction.retain_path(f"prompt-{prompt}")
            transaction.prepare_file_mutation(
                target,
                prompt_preimages[prompt],
                retained_prompt,
                prompt_contents[prompt],
                0o644,
            )
            try:
                postimage = atomic_write_text_cas(
                    target,
                    prompt_contents[prompt],
                    prompt_preimages[prompt],
                    label=f"Codex prompt {prompt}",
                    mode=0o644,
                    retain_preimage=retained_prompt,
                )
            except InstallPreimageDrift:
                transaction.preserve_on_rollback(target)
                raise
            transaction.expect_rollback_state(
                target,
                postimage,
                retained_preimage=retained_prompt,
            )
        for source, target, preimage, label, retain_label in (
            (
                staged_skill,
                skill_dir,
                skill_preimage,
                "jstack-dev skill",
                "jstack-dev-skill",
            ),
            (
                staged_audit_skill,
                audit_skill_dir,
                audit_skill_preimage,
                "jstack-audit skill",
                "jstack-audit-skill",
            ),
            (
                staged_loop_skill,
                loop_skill_dir,
                loop_skill_preimage,
                "jstack-loop skill",
                "jstack-loop-skill",
            ),
            (
                staged_product_ui_skill,
                product_ui_skill_dir,
                product_ui_preimage,
                "Product UI skill",
                "product-ui-design",
            ),
            (
                staged_mcp,
                mcp_dir,
                mcp_preimage,
                "JStack MCP tree",
                "jstack-mcp",
            ),
        ):
            retained_tree = transaction.retain_path(retain_label)
            transaction.prepare_tree_mutation(
                target,
                preimage,
                retained_tree,
                source,
                label=label,
            )
            try:
                postimage = copytree_replace_cas(
                    source,
                    target,
                    preimage,
                    retain_preimage=retained_tree,
                    label=label,
                )
            except InstallPreimageDrift:
                transaction.preserve_on_rollback(target)
                raise
            transaction.expect_rollback_tree_state(
                target,
                postimage,
                retained_preimage=retained_tree,
            )
        retained_backup = transaction.retain_path("config-backup")
        transaction.prepare_file_mutation(
            backup,
            backup_preimage,
            retained_backup,
            original,
            0o600,
        )
        backup_postimage = atomic_write_text_cas(
            backup,
            original,
            backup_preimage,
            label="Codex JStack config backup",
            retain_preimage=retained_backup,
        )
        transaction.expect_rollback_state(
            backup,
            backup_postimage,
            retained_preimage=retained_backup,
        )
        retained_config = transaction.retain_path("config.toml")
        transaction.prepare_file_mutation(
            config_path,
            config_preimage,
            retained_config,
            updated,
            0o600,
        )
        config_postimage = atomic_write_text_cas(
            config_path,
            updated,
            config_preimage,
            label="Codex config.toml",
            retain_preimage=retained_config,
        )
        transaction.expect_rollback_state(
            config_path,
            config_postimage,
            retained_preimage=retained_config,
        )
        if agents_preimage is not None:
            retained_agents = transaction.retain_path("AGENTS.md")
            agents_mode = (
                stat.S_IMODE(agents_preimage.stat_identity[2])
                if agents_preimage.stat_identity is not None
                else 0o644
            )
            transaction.prepare_file_mutation(
                agents_preimage.path,
                InstallFileState(
                    agents_preimage.exists,
                    agents_preimage.content,
                    agents_preimage.stat_identity,
                ),
                retained_agents,
                render_managed_agents(agents_preimage.content).decode("utf-8"),
                agents_mode,
            )
            agents_postimage = write_managed_agents(
                agents_preimage,
                retain_preimage=retained_agents,
            )
            transaction.expect_rollback_state(
                agents_preimage.path,
                agents_postimage,
                retained_preimage=retained_agents,
            )
    except BaseException:
        transaction.rollback()
        raise
    transaction.commit()

    return {
        "promptsDir": prompts_dir,
        "skillDir": skill_dir,
        "auditSkillDir": audit_skill_dir,
        "loopSkillDir": loop_skill_dir,
        "productUiSkillDir": product_ui_skill_dir,
        "mcpDir": mcp_dir,
        "configPath": config_path,
        "backup": backup,
        "archivedPrompt": archived_prompt,
        "archivedSkill": archived_skill,
        "agentsPath": codex_home_input / "AGENTS.md" if agents_preimage is not None else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    parser.add_argument(
        "--manage-agents",
        action="store_true",
        help="Install the bounded JStack Product UI block in global AGENTS.md",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    codex_home = Path(args.codex_home)
    outcome = install(repo_root, codex_home, manage_agents=args.manage_agents)
    prompts_dir = outcome["promptsDir"]
    skill_dir = outcome["skillDir"]
    audit_skill_dir = outcome["auditSkillDir"]
    loop_skill_dir = outcome["loopSkillDir"]
    product_ui_skill_dir = outcome["productUiSkillDir"]
    mcp_dir = outcome["mcpDir"]
    config_path = outcome["configPath"]
    backup = outcome["backup"]
    archived_prompt = outcome["archivedPrompt"]
    archived_skill = outcome["archivedSkill"]
    agents_path = outcome["agentsPath"]

    print("Installed JStack prompts:")
    for prompt in PROMPTS:
        print(f"  - {prompts_dir / prompt}")
    print(f"Installed jstack-dev skill to {skill_dir}")
    print(f"Installed jstack-audit skill to {audit_skill_dir}")
    print(f"Installed jstack-loop skill to {loop_skill_dir}")
    print(f"Installed product-ui-design skill to {product_ui_skill_dir}")
    print(f"Installed JStack MCP to {mcp_dir}")
    print(f"Updated Codex config: {config_path}")
    print(f"Backup written: {backup}")
    if archived_prompt:
        print(f"Archived old /gstack-dev prompt: {archived_prompt}")
    if archived_skill:
        print(f"Archived old gstack-dev skill: {archived_skill}")
    if agents_path:
        print(f"Updated managed JStack Product UI block in {agents_path}")
    print("Restart Codex or open a new thread for command and MCP changes to load.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
