"""OpenSSH-backed human-review signatures for the Beta.1 proof study.

The private reviewer roster is a closed JSON object whose keys are reviewer
identifier digests and whose values are OpenSSH public keys.  A reviewer
identifier is the lowercase SHA-256 digest of the normalized ``type base64``
public-key text; comments are deliberately excluded from both the digest and
the generated ``allowed_signers`` file.

Primary reviewers sign the canonical JSON bytes of their complete review
submission.  An adjudicator signs the canonical JSON bytes of the complete
review finalization.  Both use the fixed ``jstack-beta1-review-v1`` SSH
signature namespace.  Private keys are never loaded by this module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .common import ProofPlaneError, canonical_bytes, exact_fields, rfc3339_timestamp
from .review import FINALIZATION_SCHEMA, validate_submission


REVIEW_SIGNATURE_NAMESPACE = "jstack-beta1-review-v1"
MAX_ROSTER_BYTES = 1_000_000
MAX_ROSTER_ENTRIES = 1_024
MAX_PUBLIC_KEY_BYTES = 16_384
MAX_SIGNATURE_BYTES = 65_536
MAX_SIGNED_PAYLOAD_BYTES = 1_000_000
SSH_KEYGEN_TIMEOUT_SECONDS = 10
SSH_KEYGEN_OUTPUT_BYTES = 65_536

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_KEY_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$")
_ARMOR_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")
_SIGNATURE_BEGIN = "-----BEGIN SSH SIGNATURE-----"
_SIGNATURE_END = "-----END SSH SIGNATURE-----"


SignatureCallback = Callable[[Any, Mapping[str, Any]], bool]


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _read_bounded_regular(path: Path, *, maximum_bytes: int, field: str) -> bytes:
    """Read one regular file without following a final-component symlink."""

    path = Path(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("could not inspect %s: %s" % (field, exc)) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("%s must be a regular, non-symlink file" % field)
    if before.st_size > maximum_bytes:
        raise ProofPlaneError("%s exceeds the %d-byte limit" % (field, maximum_bytes))
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProofPlaneError("could not open %s: %s" % (field, exc)) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ProofPlaneError("%s changed while it was being opened" % field)
        if opened.st_size > maximum_bytes:
            raise ProofPlaneError("%s exceeds the %d-byte limit" % (field, maximum_bytes))
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        result = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(result) > maximum_bytes:
        raise ProofPlaneError("%s exceeds the %d-byte limit" % (field, maximum_bytes))
    return result


def normalize_openssh_public_key(value: Any) -> str:
    """Return the unique ``key-type base64`` representation of a public key."""

    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_PUBLIC_KEY_BYTES:
        raise ProofPlaneError("reviewer public key must be a bounded non-empty string")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ProofPlaneError("reviewer public key must contain exactly one text line")
    parts = value.strip().split()
    if len(parts) < 2:
        raise ProofPlaneError("reviewer public key is not OpenSSH public-key text")
    key_type, encoded = parts[0], parts[1]
    if _KEY_TYPE_PATTERN.fullmatch(key_type) is None:
        raise ProofPlaneError("reviewer public key has an invalid key type")
    try:
        key_type.encode("ascii")
        encoded.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProofPlaneError("reviewer public key type and body must be ASCII") from exc
    if not encoded or len(encoded) > MAX_PUBLIC_KEY_BYTES or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is None:
        raise ProofPlaneError("reviewer public key has malformed base64")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProofPlaneError("reviewer public key has malformed base64") from exc
    if len(decoded) < 4 or len(decoded) > MAX_PUBLIC_KEY_BYTES:
        raise ProofPlaneError("reviewer public key blob is outside the closed size limit")
    declared_length = struct.unpack(">I", decoded[:4])[0]
    if declared_length < 1 or declared_length > 128 or 4 + declared_length > len(decoded):
        raise ProofPlaneError("reviewer public key blob has an invalid algorithm field")
    try:
        embedded_type = decoded[4 : 4 + declared_length].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProofPlaneError("reviewer public key blob has a non-ASCII algorithm") from exc
    if embedded_type != key_type:
        raise ProofPlaneError("reviewer public key text and blob key types do not match")
    canonical_body = base64.b64encode(decoded).decode("ascii")
    return "%s %s" % (key_type, canonical_body)


def reviewer_id_digest(public_key_text: Any) -> str:
    """Derive the roster identifier for one normalized OpenSSH public key."""

    normalized = normalize_openssh_public_key(public_key_text)
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _decode_roster(raw: bytes) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("reviewer roster contains duplicate reviewer digest %r" % key)
            result[key] = item
        return result

    def reject_constant(item: str) -> None:
        raise ProofPlaneError("reviewer roster contains non-finite number %s" % item)

    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("reviewer roster is not valid unambiguous UTF-8 JSON: %s" % exc) from exc
    if not isinstance(value, Mapping):
        raise ProofPlaneError("reviewer roster must be a JSON object")
    return value


def validate_reviewer_roster(value: Mapping[str, Any]) -> Dict[str, str]:
    """Validate and close a reviewer-digest to public-key mapping."""

    if not isinstance(value, Mapping) or not value:
        raise ProofPlaneError("reviewer roster must be a non-empty mapping")
    if len(value) > MAX_ROSTER_ENTRIES:
        raise ProofPlaneError("reviewer roster exceeds the %d-entry limit" % MAX_ROSTER_ENTRIES)
    normalized: Dict[str, str] = {}
    seen_keys = set()
    for reviewer, public_key in value.items():
        reviewer = _sha256(reviewer, "reviewer roster key")
        key = normalize_openssh_public_key(public_key)
        expected = hashlib.sha256(key.encode("ascii")).hexdigest()
        if reviewer != expected:
            raise ProofPlaneError("reviewer roster digest does not match its normalized public key")
        if key in seen_keys:
            raise ProofPlaneError("one reviewer public key is duplicated in the closed roster")
        normalized[reviewer] = key
        seen_keys.add(key)
    if len(canonical_bytes(normalized)) > MAX_ROSTER_BYTES:
        raise ProofPlaneError("reviewer roster exceeds the canonical size limit")
    return normalized


def load_reviewer_roster(path: Path) -> Dict[str, str]:
    """Load a bounded, regular, non-symlink private roster file."""

    path = Path(path)
    if os.name == "posix":
        try:
            inspected = path.lstat()
        except OSError as exc:
            raise ProofPlaneError("could not inspect reviewer roster: %s" % exc) from exc
        if stat.S_ISLNK(inspected.st_mode) or not stat.S_ISREG(inspected.st_mode):
            raise ProofPlaneError("reviewer roster must be a regular, non-symlink file")
        permissions = stat.S_IMODE(inspected.st_mode)
        if permissions & 0o077:
            raise ProofPlaneError("private reviewer roster must not grant group or other permissions")
    raw = _read_bounded_regular(
        path,
        maximum_bytes=MAX_ROSTER_BYTES,
        field="reviewer roster",
    )
    return validate_reviewer_roster(_decode_roster(raw))


def _system_ssh_keygen(executable: Optional[Path]) -> Path:
    if executable is None:
        candidates = [
            Path("/usr/bin/ssh-keygen"),
            Path("/bin/ssh-keygen"),
            Path("/usr/local/bin/ssh-keygen"),
            Path("/opt/homebrew/bin/ssh-keygen"),
        ]
        windows = os.environ.get("WINDIR")
        if windows:
            candidates.append(Path(windows) / "System32" / "OpenSSH" / "ssh-keygen.exe")
        discovered = shutil.which("ssh-keygen", path=os.defpath)
        if discovered:
            candidates.append(Path(discovered))
        selected = None
        for candidate in candidates:
            try:
                inspected = candidate.lstat()
            except OSError:
                continue
            if (
                stat.S_ISREG(inspected.st_mode)
                and not stat.S_ISLNK(inspected.st_mode)
                and os.access(candidate, os.X_OK)
            ):
                selected = candidate
                break
        if selected is None:
            raise ProofPlaneError("system ssh-keygen executable is unavailable")
    else:
        selected = Path(executable)
        if not selected.is_absolute():
            raise ProofPlaneError("ssh-keygen executable must be an absolute system path")
    try:
        inspected = selected.lstat()
    except OSError as exc:
        raise ProofPlaneError("system ssh-keygen executable is unavailable") from exc
    if stat.S_ISLNK(inspected.st_mode) or not stat.S_ISREG(inspected.st_mode):
        raise ProofPlaneError("system ssh-keygen must be a regular, non-symlink executable")
    if not os.access(selected, os.X_OK):
        raise ProofPlaneError("system ssh-keygen is not executable")
    return selected.resolve()


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - the Beta.1 runner is POSIX, kept import-safe.
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _run_ssh_keygen(
    executable: Path,
    args: Tuple[str, ...],
    *,
    stdin: bytes,
) -> subprocess.CompletedProcess[bytes]:
    if len(stdin) > MAX_SIGNED_PAYLOAD_BYTES:
        raise ProofPlaneError("signed review payload exceeds the 1 MB limit")
    command = [str(executable)] + list(args)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    with tempfile.TemporaryFile() as input_file, tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        input_file.write(stdin)
        input_file.seek(0)
        try:
            process = subprocess.Popen(
                command,
                env=environment,
                stdin=input_file,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProofPlaneError("could not start system ssh-keygen verifier") from exc
        deadline = time.monotonic() + SSH_KEYGEN_TIMEOUT_SECONDS
        failure: Optional[str] = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "system ssh-keygen verifier timed out"
                break
            captured = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
            if captured > SSH_KEYGEN_OUTPUT_BYTES:
                failure = "system ssh-keygen verifier exceeded the output limit"
                break
            time.sleep(0.01)
        if failure is not None:
            _kill_process(process)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            _kill_process(process)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise ProofPlaneError("system ssh-keygen verifier could not be reaped") from exc
        captured = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
        if failure is None and captured > SSH_KEYGEN_OUTPUT_BYTES:
            failure = "system ssh-keygen verifier exceeded the output limit"
        if failure is not None:
            raise ProofPlaneError(failure)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(SSH_KEYGEN_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(SSH_KEYGEN_OUTPUT_BYTES + 1)
        if len(stdout) + len(stderr) > SSH_KEYGEN_OUTPUT_BYTES:
            raise ProofPlaneError("system ssh-keygen verifier exceeded the output limit")
        return subprocess.CompletedProcess(command, int(process.returncode), stdout, stderr)


def _signature_bytes(value: Any) -> bytes:
    if isinstance(value, Path):
        raw = _read_bounded_regular(
            value,
            maximum_bytes=MAX_SIGNATURE_BYTES,
            field="SSH review signature",
        )
    elif isinstance(value, bytes):
        raw = value
        if len(raw) > MAX_SIGNATURE_BYTES:
            raise ProofPlaneError("SSH review signature exceeds the %d-byte limit" % MAX_SIGNATURE_BYTES)
    else:
        raise ProofPlaneError("SSH review signature must be supplied as bytes or a Path")
    if not raw or b"\x00" in raw:
        raise ProofPlaneError("SSH review signature is empty or malformed")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProofPlaneError("SSH review signature armor must be ASCII") from exc
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != _SIGNATURE_BEGIN or lines[-1] != _SIGNATURE_END:
        raise ProofPlaneError("SSH review signature armor is malformed")
    armor = "".join(lines[1:-1])
    if not armor or any(not line or len(line) > 1_024 or _ARMOR_PATTERN.fullmatch(line) is None for line in lines[1:-1]):
        raise ProofPlaneError("SSH review signature armor body is malformed")
    try:
        decoded = base64.b64decode(armor, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProofPlaneError("SSH review signature armor body is malformed") from exc
    if not decoded.startswith(b"SSHSIG"):
        raise ProofPlaneError("SSH review signature does not contain an SSHSIG payload")
    return raw


def require_detached_openssh_signature(
    *,
    public_key_text: Any,
    signer_id_digest: str,
    namespace: str,
    payload: bytes,
    signed_artifact: Any,
    ssh_keygen: Optional[Path] = None,
) -> None:
    """Verify one detached SSHSIG against one explicitly bound public key."""

    public_key = normalize_openssh_public_key(public_key_text)
    signer = _sha256(signer_id_digest, "detached signature signerIdDigest")
    if signer != reviewer_id_digest(public_key):
        raise ProofPlaneError("detached signature signer digest does not match its public key")
    if (
        not isinstance(namespace, str)
        or not namespace
        or len(namespace) > 128
        or namespace != namespace.strip()
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in namespace)
    ):
        raise ProofPlaneError("detached signature namespace is invalid")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SIGNED_PAYLOAD_BYTES:
        raise ProofPlaneError("detached signature payload is empty or exceeds the closed size limit")
    signature = _signature_bytes(signed_artifact)
    executable = _system_ssh_keygen(ssh_keygen)
    _require_openssh_public_key(executable, public_key)
    with tempfile.TemporaryDirectory(prefix="jstack-detached-verify-") as temporary:
        root = Path(temporary)
        allowed = root / "allowed-signers"
        signature_path = root / "artifact.sig"
        allowed_payload = (signer + " " + public_key + "\n").encode("ascii")
        allowed_descriptor = os.open(allowed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        signature_descriptor = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(allowed_descriptor, "wb") as handle:
                handle.write(allowed_payload)
                handle.flush()
                os.fsync(handle.fileno())
            allowed_descriptor = -1
            with os.fdopen(signature_descriptor, "wb") as handle:
                handle.write(signature)
                handle.flush()
                os.fsync(handle.fileno())
            signature_descriptor = -1
        finally:
            if allowed_descriptor >= 0:
                os.close(allowed_descriptor)
            if signature_descriptor >= 0:
                os.close(signature_descriptor)
        completed = _run_ssh_keygen(
            executable,
            (
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                signer,
                "-n",
                namespace,
                "-s",
                str(signature_path),
            ),
            stdin=payload,
        )
    if completed.returncode != 0:
        raise ProofPlaneError("system ssh-keygen rejected the detached signature")


def _require_openssh_public_key(executable: Path, public_key: str) -> None:
    """Have the same OpenSSH implementation reject unsupported key blobs early."""

    with tempfile.TemporaryDirectory(prefix="jstack-review-key-") as temporary:
        key_path = Path(temporary) / "reviewer.pub"
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write((public_key + "\n").encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        completed = _run_ssh_keygen(
            executable,
            ("-l", "-f", str(key_path)),
            stdin=b"",
        )
    if completed.returncode != 0:
        raise ProofPlaneError("system ssh-keygen rejected a reviewer roster public key")


def _canonical_finalization_bytes(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("review finalization signature payload must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "packetId",
            "primarySubmissionSha256",
            "adjudicationRequired",
            "adjudicatorIdDigest",
            "finalDisposition",
            "finalMetricCounts",
            "rationaleSha256",
            "completedAt",
            "originalsRetained",
        ),
        "review finalization signature payload",
    )
    if value["schemaVersion"] != FINALIZATION_SCHEMA or value["adjudicationRequired"] is not True:
        raise ProofPlaneError("only a required adjudication finalization may be signed here")
    if not isinstance(value["packetId"], str) or not value["packetId"].startswith("packet-"):
        raise ProofPlaneError("review finalization signature packetId is invalid")
    primaries = value["primarySubmissionSha256"]
    if (
        not isinstance(primaries, list)
        or len(primaries) != 2
        or primaries != sorted(primaries)
        or len(set(primaries)) != 2
    ):
        raise ProofPlaneError("review finalization signature must bind two ordered primary submissions")
    for item in primaries:
        _sha256(item, "review finalization primary submission")
    _sha256(value["adjudicatorIdDigest"], "review finalization adjudicatorIdDigest")
    _sha256(value["rationaleSha256"], "review finalization rationaleSha256")
    if value["finalDisposition"] not in ("accepted", "rejected"):
        raise ProofPlaneError("review finalization signature disposition is invalid")
    counts = value["finalMetricCounts"]
    if not isinstance(counts, Mapping):
        raise ProofPlaneError("review finalization signature metric counts must be an object")
    count_names = (
        "falseFindingCount",
        "newCorrectnessFindings",
        "newSecurityFindings",
        "newOperationalFindings",
    )
    exact_fields(counts, count_names, "review finalization signature metric counts")
    if any(
        not isinstance(counts[name], int) or isinstance(counts[name], bool) or counts[name] < 0
        for name in count_names
    ):
        raise ProofPlaneError("review finalization signature metric counts are invalid")
    rfc3339_timestamp(value["completedAt"], "review finalization signature completedAt")
    if value["originalsRetained"] is not True:
        raise ProofPlaneError("review finalization signature must preserve the originals")
    payload = canonical_bytes(dict(value))
    if len(payload) > MAX_SIGNED_PAYLOAD_BYTES:
        raise ProofPlaneError("review finalization signature payload exceeds the 1 MB limit")
    return payload


def canonical_primary_submission_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the only byte sequence accepted for a primary review signature."""

    normalized = validate_submission(value)
    payload = canonical_bytes(normalized)
    if len(payload) > MAX_SIGNED_PAYLOAD_BYTES:
        raise ProofPlaneError("primary review signature payload exceeds the 1 MB limit")
    return payload


def canonical_adjudication_finalization_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the only byte sequence accepted for an adjudication signature."""

    return _canonical_finalization_bytes(value)


class SSHReviewSignatureVerifier:
    """Immutable verifier for primary-review and adjudication callbacks."""

    def __init__(
        self,
        roster: Mapping[str, Any],
        *,
        ssh_keygen: Optional[Path] = None,
    ) -> None:
        normalized = validate_reviewer_roster(roster)
        executable = _system_ssh_keygen(ssh_keygen)
        for public_key in normalized.values():
            _require_openssh_public_key(executable, public_key)
        self._roster = MappingProxyType(normalized)
        self._ssh_keygen = executable

    @classmethod
    def from_roster_file(
        cls,
        roster_path: Path,
        *,
        ssh_keygen: Optional[Path] = None,
    ) -> "SSHReviewSignatureVerifier":
        return cls(load_reviewer_roster(roster_path), ssh_keygen=ssh_keygen)

    @property
    def reviewer_count(self) -> int:
        return len(self._roster)

    def _require_signature(self, signed_artifact: Any, reviewer: str, payload: bytes) -> None:
        reviewer = _sha256(reviewer, "signed review reviewerIdDigest")
        public_key = self._roster.get(reviewer)
        if public_key is None:
            raise ProofPlaneError("signed review reviewer is absent from the closed roster")
        signature = _signature_bytes(signed_artifact)
        with tempfile.TemporaryDirectory(prefix="jstack-review-verify-") as temporary:
            root = Path(temporary)
            allowed = root / "allowed-signers"
            signature_path = root / "review.sig"
            allowed_payload = (reviewer + " " + public_key + "\n").encode("ascii")
            allowed_descriptor = os.open(allowed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            signature_descriptor = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(allowed_descriptor, "wb") as handle:
                    handle.write(allowed_payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                allowed_descriptor = -1
                with os.fdopen(signature_descriptor, "wb") as handle:
                    handle.write(signature)
                    handle.flush()
                    os.fsync(handle.fileno())
                signature_descriptor = -1
            finally:
                if allowed_descriptor >= 0:
                    os.close(allowed_descriptor)
                if signature_descriptor >= 0:
                    os.close(signature_descriptor)
            completed = _run_ssh_keygen(
                self._ssh_keygen,
                (
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed),
                    "-I",
                    reviewer,
                    "-n",
                    REVIEW_SIGNATURE_NAMESPACE,
                    "-s",
                    str(signature_path),
                ),
                stdin=payload,
            )
        if completed.returncode != 0:
            raise ProofPlaneError("system ssh-keygen rejected the human-review signature")

    def require_primary(self, signed_artifact: Any, submission: Mapping[str, Any]) -> None:
        payload = canonical_primary_submission_bytes(submission)
        self._require_signature(signed_artifact, submission["reviewerIdDigest"], payload)

    def require_adjudication(self, signed_artifact: Any, finalization: Mapping[str, Any]) -> None:
        payload = canonical_adjudication_finalization_bytes(finalization)
        self._require_signature(signed_artifact, finalization["adjudicatorIdDigest"], payload)

    def verify_primary(self, signed_artifact: Any, submission: Mapping[str, Any]) -> bool:
        try:
            self.require_primary(signed_artifact, submission)
        except (ProofPlaneError, OSError, subprocess.SubprocessError, TypeError, ValueError):
            return False
        return True

    def verify_adjudication(self, signed_artifact: Any, finalization: Mapping[str, Any]) -> bool:
        try:
            self.require_adjudication(signed_artifact, finalization)
        except (ProofPlaneError, OSError, subprocess.SubprocessError, TypeError, ValueError):
            return False
        return True


def make_evidence_signature_verifiers(
    roster_path: Path,
    *,
    ssh_keygen: Optional[Path] = None,
) -> Dict[str, SignatureCallback]:
    """Return kwargs-compatible callbacks for ``verify_attestation_evidence``."""

    verifier = SSHReviewSignatureVerifier.from_roster_file(
        roster_path,
        ssh_keygen=ssh_keygen,
    )
    return {
        "signed_review_verifier": verifier.verify_primary,
        "adjudication_verifier": verifier.verify_adjudication,
    }


__all__ = [
    "MAX_PUBLIC_KEY_BYTES",
    "MAX_ROSTER_BYTES",
    "MAX_ROSTER_ENTRIES",
    "MAX_SIGNATURE_BYTES",
    "MAX_SIGNED_PAYLOAD_BYTES",
    "REVIEW_SIGNATURE_NAMESPACE",
    "SSHReviewSignatureVerifier",
    "canonical_adjudication_finalization_bytes",
    "canonical_primary_submission_bytes",
    "load_reviewer_roster",
    "make_evidence_signature_verifiers",
    "normalize_openssh_public_key",
    "require_detached_openssh_signature",
    "reviewer_id_digest",
    "validate_reviewer_roster",
]
