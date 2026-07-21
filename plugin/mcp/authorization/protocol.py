"""Fail-closed, one-action authorization state for external JStack mutations.

This module never performs Git, provider, deployment, or production actions.
It validates an exact signed intent and consumes that authority once before a
separate executor performs the approved operation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


CHALLENGE_SCHEMA = "jstack.external-action.challenge.v1"
ATTESTATION_SCHEMA = "jstack.external-action.attestation.v1"
GRANT_SCHEMA = "jstack.external-action.grant.v1"
STATE_SCHEMA = "jstack.external-action.state.v1"
CONSUMPTION_SCHEMA = "jstack.external-action.consumption.v1"

ACTIONS = (
    "repository_create",
    "remote_add",
    "remote_change",
    "commit",
    "push",
    "pull_request_create",
    "merge",
    "tag_create",
    "release_create",
    "deploy",
    "production_mutation",
)
ACTION_ROLES = {
    "repository_create": "repository-owner",
    "remote_add": "repository-owner",
    "remote_change": "repository-owner",
    "commit": "source-owner",
    "push": "repository-owner",
    "pull_request_create": "repository-owner",
    "merge": "merge-owner",
    "tag_create": "release-owner",
    "release_create": "release-owner",
    "deploy": "deployment-owner",
    "production_mutation": "production-operator",
}
PROVIDERS = ("local-git", "github", "gitlab", "bitbucket", "azure-devops", "other")
VISIBILITIES = ("local-only", "private", "internal", "public")
NOT_APPLICABLE = "not-applicable"
MAX_AUTHORIZATION_SECONDS = 15 * 60
DEFAULT_AUTHORIZATION_SECONDS = 10 * 60
MAX_OBSERVATION_AGE_SECONDS = 5 * 60
LOCK_STALE_SECONDS = 30

_IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_AUTHORIZATION_ID = re.compile(r"authorization-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_OWNER = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,99})*"
)
_REMOTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SESSION = re.compile(r"[0-9a-f]{32}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?")
_ENVIRONMENT = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,127}")
_AMBIGUOUS = {"*", "any", "auto", "default", "later", "tbd", "unknown", "unspecified"}
_TARGET_FIELDS = {
    "provider",
    "owner",
    "repository",
    "visibility",
    "remoteName",
    "remoteUrl",
    "branch",
    "tag",
    "exactCommit",
    "targetEnvironment",
}
_BINDING_FIELDS = {
    "projectPath",
    "gitHead",
    "projectFingerprint",
    "policyDigest",
    "toolVersion",
    "serverSession",
    "currentBranch",
    "remoteSnapshotDigest",
}
_PAYLOAD_FIELDS = {
    "schemaVersion",
    "authorizationId",
    "actionSet",
    "requiredRole",
    "target",
    "binding",
    "approverId",
    "approvalReferenceDigest",
    "issuedAt",
    "expiresAt",
    "nonce",
}
_OBSERVATION_FIELDS = {
    "target",
    "providerTargetExists",
    "source",
    "observedAt",
}
_consumed_in_process: set[tuple[str, str]] = set()


class AuthorizationError(Exception):
    """Expected authorization validation or state error."""


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def now_iso() -> str:
    return now().isoformat()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def parse_time(value: Any, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise AuthorizationError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def _text(value: Any, field: str, maximum: int = 500) -> str:
    if not isinstance(value, str):
        raise AuthorizationError(f"{field} must be a string.")
    result = value.strip()
    if not result or len(result) > maximum:
        raise AuthorizationError(f"{field} must contain 1-{maximum} characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise AuthorizationError(f"{field} contains control characters.")
    if result.lower() in _AMBIGUOUS:
        raise AuthorizationError(f"{field} must be exact; ambiguous placeholders are forbidden.")
    return result


def _ref(value: Any, field: str, allow_not_applicable: bool) -> str:
    result = _text(value, field, 255)
    if allow_not_applicable and result == NOT_APPLICABLE:
        return result
    if result == NOT_APPLICABLE:
        raise AuthorizationError(f"{field} cannot be not-applicable for this action.")
    if result.startswith("-") or result.endswith(".") or result.endswith("/"):
        raise AuthorizationError(f"{field} is not a safe exact Git ref name.")
    if any(character in result for character in " ~^:?*[\\") or ".." in result or "@{" in result:
        raise AuthorizationError(f"{field} is not a safe exact Git ref name.")
    return result


def normalize_target(value: Any, action: str) -> dict[str, Any]:
    if action not in ACTIONS:
        raise AuthorizationError("Unsupported external action.")
    if not isinstance(value, dict) or set(value) != _TARGET_FIELDS:
        raise AuthorizationError(
            "target must contain exactly provider, owner, repository, visibility, remoteName, remoteUrl, branch, tag, exactCommit, and targetEnvironment."
        )
    provider = _text(value.get("provider"), "target.provider", 32).lower()
    if provider not in PROVIDERS:
        raise AuthorizationError("target.provider is unsupported.")
    owner = _text(value.get("owner"), "target.owner", 100)
    repository = _text(value.get("repository"), "target.repository", 100)
    if not _OWNER.fullmatch(owner) or not _NAME.fullmatch(repository):
        raise AuthorizationError("target.owner and target.repository must be exact safe names.")
    visibility = _text(value.get("visibility"), "target.visibility", 32).lower()
    if visibility not in VISIBILITIES:
        raise AuthorizationError("target.visibility is unsupported or ambiguous.")
    remote_name = _text(value.get("remoteName"), "target.remoteName", 64)
    remote_url = _text(value.get("remoteUrl"), "target.remoteUrl", 1000)
    branch = _ref(value.get("branch"), "target.branch", allow_not_applicable=False)
    tag_required = action in {"tag_create", "release_create"}
    tag = _ref(value.get("tag"), "target.tag", allow_not_applicable=not tag_required)
    exact_commit = _text(value.get("exactCommit"), "target.exactCommit", 64).lower()
    if not _COMMIT.fullmatch(exact_commit):
        raise AuthorizationError("target.exactCommit must be one full 40- or 64-character Git commit ID.")
    target_environment = _text(
        value.get("targetEnvironment"), "target.targetEnvironment", 128
    ).lower()
    if not _ENVIRONMENT.fullmatch(target_environment):
        raise AuthorizationError("target.targetEnvironment must be an exact safe environment identifier.")

    if provider == "local-git":
        if visibility != "local-only":
            raise AuthorizationError("local-git actions require visibility=local-only.")
        if remote_name != NOT_APPLICABLE or remote_url != NOT_APPLICABLE:
            raise AuthorizationError("local-git actions require not-applicable remote fields.")
        if target_environment != "local":
            raise AuthorizationError("local-git actions require targetEnvironment=local.")
    else:
        if visibility == "local-only":
            raise AuthorizationError("External providers require an exact non-local visibility.")
        if not _REMOTE_NAME.fullmatch(remote_name):
            raise AuthorizationError("External providers require an exact safe remoteName.")
        if remote_url == NOT_APPLICABLE or not (
            "://" in remote_url or re.fullmatch(r"[^/@\s]+@[^/:\s]+:[^\s]+", remote_url)
        ):
            raise AuthorizationError("External providers require an exact absolute or SCP-style remoteUrl.")
        if "*" in remote_url or any(token in remote_url.lower() for token in ("<owner>", "<repo>", "{owner}", "{repo}")):
            raise AuthorizationError("target.remoteUrl must not contain wildcards or placeholders.")

    external_only = {
        "repository_create",
        "remote_add",
        "remote_change",
        "push",
        "pull_request_create",
        "release_create",
        "deploy",
        "production_mutation",
    }
    if action in external_only and provider == "local-git":
        raise AuthorizationError(f"{action} requires an external provider target.")
    if action in {"commit", "tag_create"} and provider != "local-git":
        raise AuthorizationError(f"{action} must be authorized as a local-git action.")
    if action in {
        "repository_create",
        "remote_add",
        "remote_change",
        "push",
        "pull_request_create",
        "release_create",
    } and target_environment != "repository":
        raise AuthorizationError(f"{action} requires targetEnvironment=repository.")
    if action == "merge" and target_environment != ("local" if provider == "local-git" else "repository"):
        raise AuthorizationError("merge targetEnvironment does not match its provider boundary.")
    if action == "production_mutation" and not target_environment.startswith("production"):
        raise AuthorizationError("production_mutation requires an exact production targetEnvironment.")
    if action == "deploy" and target_environment in {"local", "repository"}:
        raise AuthorizationError("deploy requires an exact non-local deployment environment.")
    if not tag_required and tag != NOT_APPLICABLE:
        raise AuthorizationError(f"target.tag must be not-applicable for {action}.")

    return {
        "provider": provider,
        "owner": owner,
        "repository": repository,
        "visibility": visibility,
        "remoteName": remote_name,
        "remoteUrl": remote_url,
        "branch": branch,
        "tag": tag,
        "exactCommit": exact_commit,
        "targetEnvironment": target_environment,
    }


def normalize_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        raise AuthorizationError("authorization binding fields do not match the protocol.")
    project_path = _text(value.get("projectPath"), "binding.projectPath", 2000)
    if not Path(project_path).is_absolute():
        raise AuthorizationError("binding.projectPath must be absolute.")
    git_head = _text(value.get("gitHead"), "binding.gitHead", 64).lower()
    if not _COMMIT.fullmatch(git_head):
        raise AuthorizationError("binding.gitHead must be a full Git commit ID.")
    project_fingerprint = _text(
        value.get("projectFingerprint"), "binding.projectFingerprint", 64
    ).lower()
    policy_digest = _text(value.get("policyDigest"), "binding.policyDigest", 64).lower()
    remote_digest = _text(
        value.get("remoteSnapshotDigest"), "binding.remoteSnapshotDigest", 64
    ).lower()
    if not all(_SHA256.fullmatch(item) for item in (project_fingerprint, policy_digest, remote_digest)):
        raise AuthorizationError("binding digests must be lowercase SHA-256 values.")
    tool_version = _text(value.get("toolVersion"), "binding.toolVersion", 100)
    if not _VERSION.fullmatch(tool_version):
        raise AuthorizationError("binding.toolVersion is invalid.")
    server_session = _text(value.get("serverSession"), "binding.serverSession", 32).lower()
    if not _SESSION.fullmatch(server_session):
        raise AuthorizationError("binding.serverSession is invalid.")
    current_branch = _ref(
        value.get("currentBranch"), "binding.currentBranch", allow_not_applicable=False
    )
    return {
        "projectPath": project_path,
        "gitHead": git_head,
        "projectFingerprint": project_fingerprint,
        "policyDigest": policy_digest,
        "toolVersion": tool_version,
        "serverSession": server_session,
        "currentBranch": current_branch,
        "remoteSnapshotDigest": remote_digest,
    }


def validate_attestation_payload(
    value: Any,
    *,
    current_time: Optional[dt.datetime] = None,
    max_seconds: int = MAX_AUTHORIZATION_SECONDS,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise AuthorizationError("authorization challenge fields do not match the protocol.")
    if value.get("schemaVersion") != ATTESTATION_SCHEMA:
        raise AuthorizationError("authorization challenge schema is unsupported.")
    authorization_id = _text(
        value.get("authorizationId"), "authorizationId", 100
    )
    if not _AUTHORIZATION_ID.fullmatch(authorization_id):
        raise AuthorizationError("authorizationId is invalid.")
    action_set = value.get("actionSet")
    if not isinstance(action_set, list) or len(action_set) != 1 or action_set[0] not in ACTIONS:
        raise AuthorizationError("actionSet must contain exactly one supported action.")
    action = action_set[0]
    required_role = _text(value.get("requiredRole"), "requiredRole", 64)
    if required_role != ACTION_ROLES[action]:
        raise AuthorizationError("requiredRole does not match the exact action.")
    target = normalize_target(value.get("target"), action)
    binding = normalize_binding(value.get("binding"))
    approver_id = _text(value.get("approverId"), "approverId", 64)
    if not _IDENTIFIER.fullmatch(approver_id):
        raise AuthorizationError("approverId must use lowercase hyphen-case.")
    reference_digest = _text(
        value.get("approvalReferenceDigest"), "approvalReferenceDigest", 64
    ).lower()
    nonce = _text(value.get("nonce"), "nonce", 32).lower()
    if not _SHA256.fullmatch(reference_digest) or not _SESSION.fullmatch(nonce):
        raise AuthorizationError("approval reference digest or nonce is invalid.")
    issued = parse_time(value.get("issuedAt"), "issuedAt")
    expires = parse_time(value.get("expiresAt"), "expiresAt")
    moment = (current_time or now()).astimezone(dt.timezone.utc)
    bounded_max = min(int(max_seconds), MAX_AUTHORIZATION_SECONDS)
    if not issued <= moment < expires:
        raise AuthorizationError("authorization challenge is not currently valid.")
    if not 0 < (expires - issued).total_seconds() <= bounded_max:
        raise AuthorizationError("authorization expiry exceeds the policy boundary.")
    return {
        "schemaVersion": ATTESTATION_SCHEMA,
        "authorizationId": authorization_id,
        "actionSet": [action],
        "requiredRole": required_role,
        "target": target,
        "binding": binding,
        "approverId": approver_id,
        "approvalReferenceDigest": reference_digest,
        "issuedAt": issued.replace(microsecond=0).isoformat(),
        "expiresAt": expires.replace(microsecond=0).isoformat(),
        "nonce": nonce,
    }


def normalize_observation(
    value: Any,
    action: str,
    *,
    expected_target: dict[str, Any],
    current_time: Optional[dt.datetime] = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _OBSERVATION_FIELDS:
        raise AuthorizationError(
            "observation must contain exactly target, providerTargetExists, source, and observedAt."
        )
    target = normalize_target(value.get("target"), action)
    if target != expected_target:
        raise AuthorizationError(
            "Provider observation does not exactly match the authorized provider, owner, repository, visibility, remote, ref, commit, and environment."
        )
    exists = value.get("providerTargetExists")
    if not isinstance(exists, bool):
        raise AuthorizationError("observation.providerTargetExists must be boolean.")
    expected_exists = action != "repository_create"
    if exists is not expected_exists:
        raise AuthorizationError(
            "Provider target existence does not match the authorized action precondition."
        )
    source = _text(value.get("source"), "observation.source", 500)
    observed = parse_time(value.get("observedAt"), "observation.observedAt")
    moment = (current_time or now()).astimezone(dt.timezone.utc)
    age = (moment - observed).total_seconds()
    if not -30 <= age <= MAX_OBSERVATION_AGE_SECONDS:
        raise AuthorizationError("Provider observation is stale or from the future.")
    return {
        "target": target,
        "providerTargetExists": exists,
        "source": source,
        "observedAt": observed.replace(microsecond=0).isoformat(),
    }


def create_attestation_payload(
    *,
    authorization_id: str,
    action: str,
    target: dict[str, Any],
    binding: dict[str, Any],
    approver_id: str,
    approval_reference_digest: str,
    nonce: str,
    valid_for_seconds: int,
    issued_at: Optional[dt.datetime] = None,
    max_seconds: int = MAX_AUTHORIZATION_SECONDS,
) -> dict[str, Any]:
    issued = (issued_at or now()).astimezone(dt.timezone.utc).replace(microsecond=0)
    requested = int(valid_for_seconds)
    if not 1 <= requested <= min(int(max_seconds), MAX_AUTHORIZATION_SECONDS):
        raise AuthorizationError("valid_for_seconds exceeds the authorization policy boundary.")
    payload = {
        "schemaVersion": ATTESTATION_SCHEMA,
        "authorizationId": authorization_id,
        "actionSet": [action],
        "requiredRole": ACTION_ROLES.get(action),
        "target": target,
        "binding": binding,
        "approverId": approver_id,
        "approvalReferenceDigest": approval_reference_digest,
        "issuedAt": issued.isoformat(),
        "expiresAt": (issued + dt.timedelta(seconds=requested)).isoformat(),
        "nonce": nonce,
    }
    return validate_attestation_payload(
        payload, current_time=issued, max_seconds=max_seconds
    )


def _safe_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise AuthorizationError("External-action state path is unsafe.")
    else:
        path.mkdir(parents=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise AuthorizationError("Could not secure external-action state directory.") from exc


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    _safe_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    _safe_directory(path.parent)
    deadline = time.monotonic() + 5
    while True:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(descriptor, (str(os.getpid()) + "\n").encode("ascii"))
            finally:
                os.close(descriptor)
            break
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > LOCK_STALE_SECONDS:
                    path.unlink()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise AuthorizationError("External-action authorization state is busy.")
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


class AuthorizationService:
    """Durable, sealed, session-bound authorization lifecycle."""

    def __init__(
        self,
        home: Path,
        project_path: Path,
        server_session: str,
        seal_secret: bytes,
    ) -> None:
        if not _SESSION.fullmatch(server_session) or len(seal_secret) < 32:
            raise AuthorizationError("Authorization service binding is invalid.")
        project = project_path.resolve()
        key = hashlib.sha256(str(project).encode("utf-8")).hexdigest()[:16]
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", project.name).strip("-") or "project"
        jstack_root = home.expanduser() / ".jstack"
        external_root = jstack_root / "external-actions"
        self.root = external_root / f"{slug}-{key}"
        self.challenge_root = self.root / "challenges"
        self.state_root = self.root / "authorizations"
        self.lock_path = self.root / ".lock"
        self.project_path = str(project)
        self.server_session = server_session
        self.seal_secret = seal_secret
        for directory in (
            jstack_root,
            external_root,
            self.root,
            self.challenge_root,
            self.state_root,
        ):
            _safe_directory(directory)

    def _seal(self, value: dict[str, Any]) -> dict[str, Any]:
        body = dict(value)
        body.pop("integrity", None)
        signature = hmac.new(self.seal_secret, canonical(body), hashlib.sha256).hexdigest()
        return {**body, "integrity": "sha256:" + signature}

    def _read(self, path: Path, label: str) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            raise AuthorizationError(f"{label} is missing or unsafe.")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AuthorizationError(f"{label} is malformed.") from exc
        if not isinstance(value, dict) or not isinstance(value.get("integrity"), str):
            raise AuthorizationError(f"{label} integrity metadata is missing.")
        supplied = value["integrity"]
        body = dict(value)
        body.pop("integrity", None)
        expected = "sha256:" + hmac.new(
            self.seal_secret, canonical(body), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise AuthorizationError(f"{label} failed its session integrity check.")
        return body

    def create_challenge(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = validate_attestation_payload(payload)
        if normalized["binding"]["projectPath"] != self.project_path or normalized["binding"]["serverSession"] != self.server_session:
            raise AuthorizationError("Challenge does not match this project and MCP session.")
        path = self.challenge_root / f"{normalized['authorizationId']}.json"
        with _lock(self.lock_path):
            if path.exists() or (self.state_root / path.name).exists():
                raise AuthorizationError("Authorization ID has already been used.")
            record = {
                "schemaVersion": CHALLENGE_SCHEMA,
                "authorizationId": normalized["authorizationId"],
                "challengeDigest": digest(normalized),
                "payload": normalized,
                "createdAt": now_iso(),
            }
            _atomic_write(path, self._seal(record))
        return record

    def challenge(self, authorization_id: str) -> dict[str, Any]:
        if not _AUTHORIZATION_ID.fullmatch(str(authorization_id or "")):
            raise AuthorizationError("authorization_id is invalid.")
        return self._read(
            self.challenge_root / f"{authorization_id}.json", "Authorization challenge"
        )

    def authorize(
        self,
        authorization_id: str,
        payload: dict[str, Any],
        *,
        attestation_digest: str,
        current_binding: dict[str, Any],
    ) -> dict[str, Any]:
        normalized = validate_attestation_payload(payload)
        challenge = self.challenge(authorization_id)
        if digest(normalized) != challenge["challengeDigest"] or normalized != challenge["payload"]:
            raise AuthorizationError("Signed attestation does not match the server-issued challenge.")
        if normalize_binding(current_binding) != normalized["binding"]:
            raise AuthorizationError("Project, Git, policy, session, branch, or remote state drifted after the challenge.")
        if not _SHA256.fullmatch(attestation_digest):
            raise AuthorizationError("attestation_digest is invalid.")
        state_path = self.state_root / f"{authorization_id}.json"
        with _lock(self.lock_path):
            if state_path.exists():
                raise AuthorizationError("This authorization challenge was already resolved; replay is forbidden.")
            state = {
                "schemaVersion": STATE_SCHEMA,
                "authorizationId": authorization_id,
                "status": "approved",
                "challengeDigest": challenge["challengeDigest"],
                "attestationDigest": attestation_digest,
                "action": normalized["actionSet"][0],
                "target": normalized["target"],
                "binding": normalized["binding"],
                "approverId": normalized["approverId"],
                "approvalReferenceDigest": normalized["approvalReferenceDigest"],
                "approvedAt": now_iso(),
                "expiresAt": normalized["expiresAt"],
                "consumption": None,
            }
            _atomic_write(state_path, self._seal(state))
        return {**state, "schemaVersion": GRANT_SCHEMA}

    def consume(
        self,
        authorization_id: str,
        *,
        action: str,
        operation_id: str,
        authorization_receipt_digest: str,
        observation: dict[str, Any],
        current_binding: dict[str, Any],
    ) -> dict[str, Any]:
        if action not in ACTIONS:
            raise AuthorizationError("Unsupported external action.")
        if not _OPERATION_ID.fullmatch(str(operation_id or "")):
            raise AuthorizationError("operation_id is invalid.")
        if not _SHA256.fullmatch(str(authorization_receipt_digest or "")):
            raise AuthorizationError("authorization receipt digest is invalid.")
        process_key = (self.server_session, authorization_id)
        state_path = self.state_root / f"{authorization_id}.json"
        with _lock(self.lock_path):
            if process_key in _consumed_in_process:
                raise AuthorizationError("Authorization was already consumed in this MCP session; replay is forbidden.")
            state = self._read(state_path, "External-action authorization")
            if state.get("schemaVersion") != STATE_SCHEMA or state.get("status") != "approved":
                raise AuthorizationError("Authorization is not pending or was already consumed.")
            if state.get("action") != action:
                raise AuthorizationError("Requested action is not the exact authorized action; escalation is forbidden.")
            if normalize_binding(current_binding) != state.get("binding"):
                raise AuthorizationError("Project, Git, policy, session, branch, or remote state drifted after authorization.")
            if now() >= parse_time(state.get("expiresAt"), "expiresAt"):
                raise AuthorizationError("Authorization expired before consumption.")
            normalized_observation = normalize_observation(
                observation, action, expected_target=state["target"]
            )
            consumption = {
                "schemaVersion": CONSUMPTION_SCHEMA,
                "authorizationId": authorization_id,
                "operationId": operation_id,
                "action": action,
                "targetDigest": digest(state["target"]),
                "bindingDigest": digest(state["binding"]),
                "observationDigest": digest(normalized_observation),
                "authorizationReceiptDigest": authorization_receipt_digest,
                "consumedAt": now_iso(),
            }
            state["status"] = "consumed"
            state["consumption"] = consumption
            _atomic_write(state_path, self._seal(state))
            _consumed_in_process.add(process_key)
        return consumption
