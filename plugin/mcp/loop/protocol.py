"""State machine and durable storage for bounded JStack goal loops.

The protocol never executes repository commands. Codex Goal mode provides
continuation while existing JStack tools provide policy and evidence. This
module binds those decisions to an append-only, hash-chained local record.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Optional


LOOP_CONTRACT_SCHEMA = "jstack.loop.contract.v1"
LOOP_SNAPSHOT_SCHEMA = "jstack.loop.snapshot.v1"
LOOP_EVENT_SCHEMA = "jstack.loop.event.v1"
LOOP_STATUS_SCHEMA = "jstack.loop.status.v1"

EXECUTION_MODES = ("single-lead", "smart-subagents", "full-team")
AUTONOMY_LEVELS = ("L0", "L1", "L2", "L3")
RISK_TIERS = ("low", "medium", "high", "critical")
VERIFIER_TYPES = ("qa", "security", "audit", "review", "artifact", "human")
TERMINAL_STATUSES = {"succeeded", "stopped"}
WRITE_AUTONOMY = {"L2", "L3"}

MAX_EVENTS = 1000
MAX_EVENT_BYTES = 5_000_000
TERMINAL_EVENT_RESERVE_BYTES = 1_500_000
MAX_CONTRACT_REVISIONS = 100
MAX_GOAL_CHARS = 4000
MAX_SUMMARY_CHARS = 4000
MAX_CRITERIA = 50
MAX_SCOPE_PATTERNS = 100
MAX_APPROVALS = 50
LOCK_STALE_SECONDS = 30

DEFAULT_BLOCKED_ACTIONS = (
    "production-release",
    "git-push",
    "git-force",
    "destructive-git",
    "secret-access",
    "policy-weakening",
    "unapproved-protected-path-change",
    "team-mode-escalation",
)

DEFAULT_LIMITS = {
    "maxIterations": 12,
    "maxNoProgress": 3,
    "maxRepeatedFailure": 2,
    "maxElapsedMinutes": 120,
    "maxChangedFiles": 50,
}

_LOOP_ID = re.compile(r"^loop-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$")
_CRITERION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class LoopError(Exception):
    """A bounded loop protocol or persistence failure."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _now_iso() -> str:
    return _now().isoformat()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LoopError("Loop state contains a value that cannot be represented safely.") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_time(value: Any, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise LoopError(f"Loop {field} is not a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise LoopError(f"Loop {field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def _text(value: Any, field: str, *, maximum: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise LoopError(f"{field} must be a string.")
    result = value.strip()
    if required and not result:
        raise LoopError(f"{field} must not be empty.")
    if len(result) > maximum:
        raise LoopError(f"{field} exceeds the {maximum}-character limit.")
    return result


def _string_list(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    item_maximum: int = 500,
    required: bool = False,
) -> list[str]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise LoopError(f"{field} must be an array of strings.")
    if required and not value:
        raise LoopError(f"{field} must contain at least one item.")
    if len(value) > maximum_items:
        raise LoopError(f"{field} exceeds the {maximum_items}-item limit.")
    result: list[str] = []
    for index, item in enumerate(value):
        normalized = _text(item, f"{field}[{index}]", maximum=item_maximum)
        if normalized not in result:
            result.append(normalized)
    return result


def _normalize_relative_path(value: Any, field: str, *, allow_glob: bool) -> str:
    path = _text(value, field, maximum=500).replace("\\", "/")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise LoopError(f"{field} contains a control character.")
    if path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
        raise LoopError(f"{field} must be repository-relative.")
    parts = [part for part in path.split("/") if part not in {"", "."}]
    if not parts or ".." in parts or any(part.lower() == ".git" for part in parts):
        raise LoopError(f"{field} contains an unsafe repository path.")
    if not allow_glob and any(character in path for character in "*?["):
        raise LoopError(f"{field} must name one exact repository file.")
    return "/".join(parts)


def _path_matches_pattern(path: str, pattern: str) -> bool:
    path_parts = tuple(part for part in path.split("/") if part)
    pattern_parts = tuple(part for part in pattern.split("/") if part)
    memo: dict[tuple[int, int], bool] = {}

    def matches(path_index: int, pattern_index: int) -> bool:
        key = (path_index, pattern_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = matches(path_index, pattern_index + 1) or (
                path_index < len(path_parts)
                and matches(path_index + 1, pattern_index)
            )
        else:
            result = (
                path_index < len(path_parts)
                and fnmatch.fnmatchcase(path_parts[path_index], pattern_parts[pattern_index])
                and matches(path_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return matches(0, 0)


def _normalize_criteria(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise LoopError("acceptance_criteria must contain at least one criterion.")
    if len(value) > MAX_CRITERIA:
        raise LoopError(f"acceptance_criteria exceeds the {MAX_CRITERIA}-criterion limit.")
    criteria: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise LoopError(f"acceptance_criteria[{index}] must be an object.")
        unknown = sorted(set(raw) - {"id", "description", "verifier"})
        if unknown:
            raise LoopError(
                f"acceptance_criteria[{index}] contains unsupported fields: {', '.join(unknown)}"
            )
        criterion_id = _text(raw.get("id"), f"acceptance_criteria[{index}].id", maximum=64)
        if not _CRITERION_ID.fullmatch(criterion_id):
            raise LoopError(
                f"acceptance_criteria[{index}].id must use letters, numbers, dots, underscores, or hyphens."
            )
        if criterion_id in seen:
            raise LoopError(f"Duplicate acceptance criterion id: {criterion_id}")
        seen.add(criterion_id)
        description = _text(
            raw.get("description"),
            f"acceptance_criteria[{index}].description",
            maximum=1000,
        )
        verifier_raw = raw.get("verifier")
        if not isinstance(verifier_raw, dict):
            raise LoopError(f"acceptance_criteria[{index}].verifier must be an object.")
        verifier_type = str(verifier_raw.get("type") or "").strip().lower()
        if verifier_type not in VERIFIER_TYPES:
            raise LoopError(
                f"acceptance_criteria[{index}].verifier.type must be one of: {', '.join(VERIFIER_TYPES)}."
            )
        allowed_fields = {
            "qa": {"type", "commandKey"},
            "security": {"type"},
            "audit": {"type", "profile"},
            "review": {"type"},
            "artifact": {"type", "path", "sha256"},
            "human": {"type", "approvalKey"},
        }[verifier_type]
        unknown_verifier = sorted(set(verifier_raw) - allowed_fields)
        if unknown_verifier:
            raise LoopError(
                f"acceptance_criteria[{index}].verifier contains unsupported fields: "
                + ", ".join(unknown_verifier)
            )
        verifier: dict[str, Any] = {"type": verifier_type}
        if verifier_type == "qa":
            verifier["commandKey"] = _text(
                verifier_raw.get("commandKey"),
                f"acceptance_criteria[{index}].verifier.commandKey",
                maximum=200,
            )
        elif verifier_type == "audit":
            profile = str(verifier_raw.get("profile") or "standard").strip().lower()
            if profile not in {"quick", "standard", "deep", "release"}:
                raise LoopError("Audit criterion profile must be quick, standard, deep, or release.")
            verifier["profile"] = profile
        elif verifier_type == "artifact":
            verifier["path"] = _normalize_relative_path(
                verifier_raw.get("path"),
                f"acceptance_criteria[{index}].verifier.path",
                allow_glob=False,
            )
            expected = str(verifier_raw.get("sha256") or "").strip().lower()
            if expected and not re.fullmatch(r"[a-f0-9]{64}", expected):
                raise LoopError("Artifact criterion sha256 must be a 64-character lowercase SHA-256 digest.")
            verifier["sha256"] = expected or None
        elif verifier_type == "human":
            verifier["approvalKey"] = _text(
                verifier_raw.get("approvalKey"),
                f"acceptance_criteria[{index}].verifier.approvalKey",
                maximum=100,
            )
        criteria.append(
            {
                "id": criterion_id,
                "description": description,
                "verifier": verifier,
            }
        )
    return criteria


def _normalize_limits(value: Any) -> dict[str, int]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise LoopError("limits must be an object.")
    allowed = {
        "max_iterations": (1, 100, "maxIterations"),
        "max_no_progress": (1, 20, "maxNoProgress"),
        "max_repeated_failure": (1, 20, "maxRepeatedFailure"),
        "max_elapsed_minutes": (5, 1440, "maxElapsedMinutes"),
        "max_changed_files": (1, 1000, "maxChangedFiles"),
    }
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise LoopError(f"limits contains unsupported fields: {', '.join(unknown)}")
    result = dict(DEFAULT_LIMITS)
    for field, (minimum, maximum, target) in allowed.items():
        if field not in value:
            continue
        number = value[field]
        if not isinstance(number, int) or isinstance(number, bool) or not minimum <= number <= maximum:
            raise LoopError(f"limits.{field} must be an integer from {minimum} to {maximum}.")
        result[target] = number
    return result


def _normalize_approvals(value: Any, field: str = "approval_updates") -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_APPROVALS:
        raise LoopError(f"{field} must be an object with at most {MAX_APPROVALS} entries.")
    result: dict[str, str] = {}
    for key, reference in value.items():
        normalized_key = _text(key, f"{field} key", maximum=100)
        if not _CRITERION_ID.fullmatch(normalized_key):
            raise LoopError(f"{field} keys must use letters, numbers, dots, underscores, or hyphens.")
        result[normalized_key] = _text(reference, f"{field}.{normalized_key}", maximum=500)
    return result


def _criterion_composition_checks(
    criteria: list[dict[str, Any]], autonomy: str, risk: str
) -> None:
    types = {item["verifier"]["type"] for item in criteria}
    machine_types = types - {"human"}
    if sum(1 for item in criteria if item["verifier"]["type"] == "artifact") > 20:
        raise LoopError("A loop contract may contain at most 20 artifact criteria.")
    if not machine_types:
        raise LoopError("At least one acceptance criterion must be machine-verifiable.")
    if autonomy in WRITE_AUTONOMY and "review" not in types:
        raise LoopError("Write-capable loops require a deterministic review criterion.")
    if autonomy in WRITE_AUTONOMY and not (machine_types - {"review"}):
        raise LoopError("Write-capable loops require at least one outcome criterion in addition to review.")
    if risk in {"medium", "high", "critical"} and "security" not in types:
        raise LoopError(f"{risk} risk loops require a security criterion.")
    if risk in {"high", "critical"} and "audit" not in types:
        raise LoopError(f"{risk} risk loops require an audit criterion.")
    if autonomy == "L3":
        required = {"qa", "security", "audit", "review"}
        missing = sorted(required - types)
        if missing:
            raise LoopError("L3 loops require QA, security, audit, and review criteria; missing: " + ", ".join(missing))
        if "human" in types:
            raise LoopError("L3 acceptance criteria must be fully machine-verifiable.")
        for item in criteria:
            verifier = item["verifier"]
            if verifier["type"] == "artifact" and not verifier.get("sha256"):
                raise LoopError("L3 artifact criteria require an expected sha256 digest.")


def _normalize_contract_input(
    args: dict[str, Any],
    *,
    project_root: str,
    subject: dict[str, Any],
    worktree: bool,
    policy_source: Optional[str],
    policy_digest: str,
    require_clean_start: bool = True,
) -> dict[str, Any]:
    goal = _text(args.get("goal"), "goal", maximum=MAX_GOAL_CHARS)
    execution_mode = str(args.get("execution_mode") or "").strip()
    autonomy = str(args.get("autonomy_level") or "").strip().upper()
    risk = str(args.get("risk_tier") or "").strip().lower()
    if execution_mode not in EXECUTION_MODES:
        raise LoopError("execution_mode must be single-lead, smart-subagents, or full-team.")
    if autonomy not in AUTONOMY_LEVELS:
        raise LoopError("autonomy_level must be L0, L1, L2, or L3.")
    if risk not in RISK_TIERS:
        raise LoopError("risk_tier must be low, medium, high, or critical.")

    criteria = _normalize_criteria(args.get("acceptance_criteria"))
    _criterion_composition_checks(criteria, autonomy, risk)
    non_goals = _string_list(args.get("non_goals"), "non_goals", maximum_items=50)
    allowed_paths_raw = _string_list(
        args.get("allowed_paths"),
        "allowed_paths",
        maximum_items=MAX_SCOPE_PATTERNS,
        required=autonomy in WRITE_AUTONOMY,
    )
    allowed_paths = [
        _normalize_relative_path(item, f"allowed_paths[{index}]", allow_glob=True)
        for index, item in enumerate(allowed_paths_raw)
    ]
    if autonomy == "L3" and any(
        any(character in path.split("/", 1)[0] for character in "*?[")
        for path in allowed_paths
    ):
        raise LoopError(
            "L3 requires each path scope to begin with a literal repository entry; repository-wide root globs are not allowed."
        )

    mode_approval = _text(
        args.get("mode_approval_reference") or "",
        "mode_approval_reference",
        maximum=500,
        required=execution_mode != "single-lead",
    )
    autonomy_approval = _text(
        args.get("autonomy_approval_reference") or "",
        "autonomy_approval_reference",
        maximum=500,
        required=autonomy == "L3",
    )
    risk_approval = _text(
        args.get("risk_approval_reference") or "",
        "risk_approval_reference",
        maximum=500,
        required=autonomy == "L2" and risk in {"high", "critical"},
    )
    protected_approval = _text(
        args.get("protected_path_approval") or "",
        "protected_path_approval",
        maximum=500,
        required=False,
    )

    if require_clean_start and autonomy in WRITE_AUTONOMY and subject.get("clean") is not True:
        raise LoopError("Write-capable loops require a clean Git worktree at contract start.")
    if autonomy == "L3":
        if risk != "low":
            raise LoopError("L3 autonomy is allowed only for low-risk work.")
        if not worktree:
            raise LoopError("L3 autonomy requires an isolated Git worktree attested by the server.")
    if risk == "critical" and autonomy not in {"L0", "L1", "L2"}:
        raise LoopError("Critical-risk work cannot use L3 autonomy.")

    supplied_blocked = _string_list(
        args.get("blocked_actions"), "blocked_actions", maximum_items=50
    )
    blocked_actions = list(DEFAULT_BLOCKED_ACTIONS)
    for item in supplied_blocked:
        if item not in blocked_actions:
            blocked_actions.append(item)
    token_budget = args.get("token_budget")
    if token_budget is not None:
        if not isinstance(token_budget, int) or isinstance(token_budget, bool) or token_budget <= 0:
            raise LoopError("token_budget must be a positive integer when the user explicitly supplies one.")

    return {
        "schemaVersion": LOOP_CONTRACT_SCHEMA,
        "revision": 1,
        "goal": goal,
        "nonGoals": non_goals,
        "executionMode": execution_mode,
        "autonomyLevel": autonomy,
        "riskTier": risk,
        "acceptanceCriteria": criteria,
        "allowedPaths": allowed_paths,
        "blockedActions": blocked_actions,
        "requireChange": autonomy in WRITE_AUTONOMY,
        "limits": _normalize_limits(args.get("limits")),
        "tokenBudget": token_budget,
        "approvals": {
            "mode": mode_approval or None,
            "autonomy": autonomy_approval or None,
            "risk": risk_approval or None,
            "protectedPaths": protected_approval or None,
        },
        "project": {
            "gitRoot": project_root,
            "baselineCommit": subject["gitHead"],
            "baselineFingerprint": subject["projectFingerprint"],
            "baselineClean": subject["clean"],
            "worktreeAttested": worktree,
        },
        "policy": {
            "digest": policy_digest,
            "source": policy_source,
            "toolVersion": subject.get("toolVersion"),
        },
    }


def _safe_state_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LoopError(f"Loop state path is not a private directory: {path}")
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _atomic_write(path: Path, data: bytes) -> None:
    _safe_state_directory(path.parent)
    if path.exists() and path.is_symlink():
        raise LoopError(f"Refusing to write through loop-state symlink: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(path, _canonical(value) + b"\n")


def _read_json(
    path: Path, field: str, *, maximum_bytes: int = MAX_EVENT_BYTES
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise LoopError(f"Loop {field} is missing, unsafe, or exceeds its size limit.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoopError(f"Loop {field} is not valid JSON.") from exc
    if not isinstance(value, dict):
        raise LoopError(f"Loop {field} must be a JSON object.")
    return value


class _DirectoryLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.acquired = False

    def __enter__(self) -> "_DirectoryLock":
        _safe_state_directory(self.path.parent)
        deadline = time.monotonic() + 5
        while True:
            try:
                self.path.mkdir(mode=0o700)
                self.acquired = True
                try:
                    _atomic_json(
                        self.path / "owner.json",
                        {"pid": os.getpid(), "acquiredAt": _now_iso()},
                    )
                except Exception:
                    self.acquired = False
                    shutil.rmtree(self.path, ignore_errors=True)
                    raise
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:
                    age = 0
                owner_alive = False
                try:
                    owner = _read_json(
                        self.path / "owner.json",
                        "state lock owner",
                        maximum_bytes=4096,
                    )
                    pid = owner.get("pid")
                    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            owner_alive = False
                        except (PermissionError, OSError):
                            owner_alive = True
                        else:
                            owner_alive = True
                except LoopError:
                    pass
                if age > LOCK_STALE_SECONDS and not owner_alive:
                    stale = self.path.parent / f".{self.path.name}.stale-{secrets.token_hex(6)}"
                    try:
                        os.replace(self.path, stale)
                        shutil.rmtree(stale, ignore_errors=True)
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise LoopError("Another JStack loop operation holds the project state lock.")
                time.sleep(0.05)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.acquired:
            shutil.rmtree(self.path, ignore_errors=True)


class LoopService:
    """Create and advance durable loop contracts for one Git repository."""

    def __init__(self, home: Path, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        project_key = hashlib.sha256(str(self.project_root).encode("utf-8")).hexdigest()[:24]
        self.root = home.expanduser() / ".jstack" / "loops" / project_key
        _safe_state_directory(self.root)
        self.lock_path = self.root / ".state-lock"

    def _loop_dir(self, loop_id: str) -> Path:
        if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
            raise LoopError("loop_id is malformed.")
        return self.root / loop_id

    def _events(self, loop_dir: Path) -> list[dict[str, Any]]:
        path = loop_dir / "events.jsonl"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
            raise LoopError("Loop event log is missing, unsafe, or exceeds its size limit.")
        events: list[dict[str, Any]] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise LoopError("Loop event log cannot be read safely.") from exc
        if not lines or len(lines) > MAX_EVENTS:
            raise LoopError("Loop event log is empty or exceeds its event limit.")
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LoopError("Loop event log contains invalid JSON.") from exc
            if not isinstance(event, dict):
                raise LoopError("Loop event log contains a non-object event.")
            events.append(event)
        self._validate_event_values(events)
        return events

    @staticmethod
    def _validate_event_values(events: list[dict[str, Any]]) -> None:
        if not events or len(events) > MAX_EVENTS:
            raise LoopError("Loop event collection is empty or exceeds its event limit.")
        previous: Optional[str] = None
        for sequence, event in enumerate(events, start=1):
            if not isinstance(event, dict):
                raise LoopError("Loop event collection contains a non-object event.")
            supplied_hash = event.get("eventHash")
            body = {key: value for key, value in event.items() if key != "eventHash"}
            checks = {
                "schema": body.get("schemaVersion") == LOOP_EVENT_SCHEMA,
                "sequence": body.get("sequence") == sequence,
                "previous": body.get("previousHash") == previous,
                "hash": supplied_hash == _digest(body),
            }
            if not all(checks.values()):
                raise LoopError("Loop event hash chain validation failed.")
            previous = str(supplied_hash)

    def _validate_contract_history(
        self,
        loop_dir: Path,
        contract: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        revision = contract.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise LoopError("Loop contract revision is malformed.")
        contracts_dir = loop_dir / "contracts"
        if contracts_dir.is_symlink() or not contracts_dir.is_dir():
            raise LoopError("Loop contract history is missing or unsafe.")

        history: list[dict[str, Any]] = []
        digests: list[str] = []
        for number in range(1, revision + 1):
            item = _read_json(contracts_dir / f"{number:04d}.json", "contract history")
            checks = {
                "schema": item.get("schemaVersion") == LOOP_CONTRACT_SCHEMA,
                "loop": item.get("loopId") == contract.get("loopId"),
                "revision": item.get("revision") == number,
                "project": item.get("project", {}).get("gitRoot") == str(self.project_root),
            }
            if not all(checks.values()):
                raise LoopError("Loop contract history failed integrity validation.")
            history.append(item)
            digests.append(_digest(item))

        if _digest(contract) != digests[-1]:
            raise LoopError("Current loop contract does not match its versioned history.")
        if any(event.get("loopId") != contract.get("loopId") for event in events):
            raise LoopError("Loop event history contains a mismatched loop identifier.")

        start_events = [event for event in events if event.get("eventType") == "loop-started"]
        revision_events = [
            event for event in events if event.get("eventType") == "contract-revised"
        ]
        if (
            len(start_events) != 1
            or start_events[0].get("sequence") != 1
            or not isinstance(start_events[0].get("payload"), dict)
            or start_events[0]["payload"].get("contractDigest") != digests[0]
            or len(revision_events) != revision - 1
        ):
            raise LoopError("Loop contract history does not match its event chain.")
        for index, event in enumerate(revision_events):
            payload = event.get("payload")
            if not isinstance(payload, dict) or (
                payload.get("oldContractDigest") != digests[index]
                or payload.get("newContractDigest") != digests[index + 1]
            ):
                raise LoopError("Loop contract revision chain failed integrity validation.")

    def _recover_pending(self, loop_dir: Path) -> None:
        pending_path = loop_dir / "pending.json"
        if not pending_path.exists():
            return
        pending = _read_json(
            pending_path,
            "pending transaction",
            maximum_bytes=MAX_EVENT_BYTES * 2,
        )
        if pending.get("schemaVersion") != "jstack.loop.transaction.v1":
            raise LoopError("Loop pending transaction schema is unsupported.")
        contract = pending.get("contract")
        snapshot = pending.get("snapshot")
        events = pending.get("events")
        if not isinstance(contract, dict) or not isinstance(snapshot, dict) or not isinstance(events, list):
            raise LoopError("Loop pending transaction is malformed.")
        self._validate_event_values(events)
        checks = {
            "contractSchema": contract.get("schemaVersion") == LOOP_CONTRACT_SCHEMA,
            "snapshotSchema": snapshot.get("schemaVersion") == LOOP_SNAPSHOT_SCHEMA,
            "loop": contract.get("loopId") == snapshot.get("loopId") == events[-1].get("loopId"),
            "project": contract.get("project", {}).get("gitRoot") == str(self.project_root),
            "contractDigest": snapshot.get("contractDigest") == _digest(contract),
            "eventHash": snapshot.get("latestEventHash") == events[-1].get("eventHash"),
            "eventSequence": snapshot.get("eventSequence") == events[-1].get("sequence"),
        }
        if not all(checks.values()):
            raise LoopError("Loop pending transaction failed integrity validation.")
        self._validate_snapshot_binding(snapshot, events[-1])
        self._write_contract(loop_dir, contract)
        _atomic_write(loop_dir / "events.jsonl", b"".join(_canonical(item) + b"\n" for item in events))
        _atomic_json(loop_dir / "snapshot.json", snapshot)
        pending_path.unlink()

    def _load(self, loop_id: str) -> tuple[Path, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        loop_dir = self._loop_dir(loop_id)
        if loop_dir.is_symlink() or not loop_dir.is_dir():
            raise LoopError(f"Unknown loop_id: {loop_id}")
        self._recover_pending(loop_dir)
        contract = _read_json(loop_dir / "contract.json", "contract")
        snapshot = _read_json(loop_dir / "snapshot.json", "snapshot")
        events = self._events(loop_dir)
        if contract.get("schemaVersion") != LOOP_CONTRACT_SCHEMA:
            raise LoopError("Loop contract schema is unsupported.")
        if snapshot.get("schemaVersion") != LOOP_SNAPSHOT_SCHEMA:
            raise LoopError("Loop snapshot schema is unsupported.")
        self._validate_contract_history(loop_dir, contract, events)
        checks = {
            "loop": (
                snapshot.get("loopId") == loop_id
                and contract.get("loopId") == loop_id
                and events[-1].get("loopId") == loop_id
            ),
            "project": contract.get("project", {}).get("gitRoot") == str(self.project_root),
            "contract": snapshot.get("contractDigest") == _digest(contract),
            "event": snapshot.get("latestEventHash") == events[-1].get("eventHash"),
            "sequence": snapshot.get("eventSequence") == events[-1].get("sequence"),
        }
        if not all(checks.values()):
            raise LoopError("Loop contract, snapshot, or event log binding validation failed.")
        self._validate_snapshot_binding(snapshot, events[-1])
        return loop_dir, contract, snapshot, events

    def _append_event(
        self,
        loop_dir: Path,
        events: list[dict[str, Any]],
        loop_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        terminal_event = event_type in {
            "loop-stopped",
            "loop-succeeded",
            "completion-revalidated",
        }
        event_count_limit = MAX_EVENTS if terminal_event else MAX_EVENTS - 1
        if len(events) >= event_count_limit:
            raise LoopError(
                "Loop event capacity reached. Finalize if current evidence is complete, or stop this loop and start a continuation contract."
            )
        body = {
            "schemaVersion": LOOP_EVENT_SCHEMA,
            "loopId": loop_id,
            "sequence": len(events) + 1,
            "eventType": event_type,
            "occurredAt": _now_iso(),
            "previousHash": events[-1]["eventHash"] if events else None,
            "payload": payload,
        }
        event = {**body, "eventHash": _digest(body)}
        rendered = b"".join(_canonical(item) + b"\n" for item in [*events, event])
        byte_limit = (
            MAX_EVENT_BYTES
            if terminal_event
            else MAX_EVENT_BYTES - TERMINAL_EVENT_RESERVE_BYTES
        )
        if len(rendered) > byte_limit:
            raise LoopError(
                "Loop event capacity reached. Finalize if current evidence is complete, or stop this loop and start a continuation contract."
            )
        events.append(event)
        return event

    def _write_contract(self, loop_dir: Path, contract: dict[str, Any]) -> None:
        revision = int(contract["revision"])
        _safe_state_directory(loop_dir / "contracts")
        _atomic_json(loop_dir / "contracts" / f"{revision:04d}.json", contract)
        _atomic_json(loop_dir / "contract.json", contract)

    @staticmethod
    def _snapshot_digest(snapshot: dict[str, Any]) -> str:
        return _digest(
            {
                key: value
                for key, value in snapshot.items()
                if key != "latestEventHash"
            }
        )

    @staticmethod
    def _prepare_snapshot(snapshot: dict[str, Any], event: dict[str, Any]) -> None:
        snapshot["updatedAt"] = event["occurredAt"]
        snapshot["eventSequence"] = event["sequence"]
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise LoopError("Loop event payload is malformed.")
        payload["snapshotDigest"] = LoopService._snapshot_digest(snapshot)
        body = {key: value for key, value in event.items() if key != "eventHash"}
        event["eventHash"] = _digest(body)
        snapshot["latestEventHash"] = event["eventHash"]

    @staticmethod
    def _validate_snapshot_binding(
        snapshot: dict[str, Any], event: dict[str, Any]
    ) -> None:
        payload = event.get("payload")
        if (
            not isinstance(payload, dict)
            or payload.get("snapshotDigest") != LoopService._snapshot_digest(snapshot)
        ):
            raise LoopError("Loop snapshot binding validation failed.")

    def _commit_state(
        self,
        loop_dir: Path,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        self._validate_event_values(events)
        rendered_events = b"".join(_canonical(item) + b"\n" for item in events)
        terminal_event = events[-1].get("eventType") in {
            "loop-stopped",
            "loop-succeeded",
            "completion-revalidated",
        }
        byte_limit = (
            MAX_EVENT_BYTES
            if terminal_event
            else MAX_EVENT_BYTES - TERMINAL_EVENT_RESERVE_BYTES
        )
        if len(rendered_events) > byte_limit:
            raise LoopError(
                "Loop event capacity reached. Finalize if current evidence is complete, or stop this loop and start a continuation contract."
            )
        self._validate_snapshot_binding(snapshot, events[-1])
        pending = {
            "schemaVersion": "jstack.loop.transaction.v1",
            "contract": contract,
            "snapshot": snapshot,
            "events": events,
        }
        if len(_canonical(pending)) > MAX_EVENT_BYTES * 2:
            raise LoopError("Loop transaction exceeds its size limit.")
        pending_path = loop_dir / "pending.json"
        _atomic_json(pending_path, pending)
        self._write_contract(loop_dir, contract)
        _atomic_write(loop_dir / "events.jsonl", rendered_events)
        _atomic_json(loop_dir / "snapshot.json", snapshot)
        pending_path.unlink()

    def _active_loop(self) -> Optional[str]:
        path = self.root / "active.json"
        if not path.exists():
            return None
        value = _read_json(path, "active lease")
        loop_id = value.get("loopId")
        if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
            raise LoopError("Loop active lease is malformed.")
        try:
            _, contract, snapshot, _ = self._load(loop_id)
        except LoopError:
            raise LoopError("Loop active lease cannot be reconciled; inspect local state before continuing.")
        if (
            snapshot.get("status") in TERMINAL_STATUSES
            or contract.get("autonomyLevel") not in WRITE_AUTONOMY
        ):
            (self.root / "active.json").unlink(missing_ok=True)
            return None
        return loop_id

    def _set_active(self, loop_id: str) -> None:
        _atomic_json(self.root / "active.json", {"loopId": loop_id, "updatedAt": _now_iso()})

    def _set_latest(self, loop_id: str) -> None:
        _atomic_json(self.root / "latest.json", {"loopId": loop_id, "updatedAt": _now_iso()})

    def _latest_loop(self) -> Optional[str]:
        path = self.root / "latest.json"
        if not path.exists():
            return None
        value = _read_json(path, "latest loop reference")
        loop_id = value.get("loopId")
        if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
            raise LoopError("Loop latest reference is malformed.")
        return loop_id

    def _release_active(self, loop_id: str) -> None:
        path = self.root / "active.json"
        if not path.exists():
            return
        value = _read_json(path, "active lease")
        if value.get("loopId") == loop_id:
            path.unlink()

    def start(
        self,
        args: dict[str, Any],
        *,
        subject: dict[str, Any],
        worktree: bool,
        policy_source: Optional[str],
        policy_digest: str,
    ) -> dict[str, Any]:
        contract = _normalize_contract_input(
            args,
            project_root=str(self.project_root),
            subject=subject,
            worktree=worktree,
            policy_source=policy_source,
            policy_digest=policy_digest,
            require_clean_start=True,
        )
        with _DirectoryLock(self.lock_path):
            if contract["autonomyLevel"] in WRITE_AUTONOMY:
                active = self._active_loop()
                if active:
                    raise LoopError(
                        f"Write-capable loop {active} already owns this repository. Finalize or stop it first."
                    )
            loop_id = _now().strftime("loop-%Y%m%dT%H%M%SZ-") + secrets.token_hex(6)
            loop_dir = self._loop_dir(loop_id)
            _safe_state_directory(loop_dir)
            contract["loopId"] = loop_id
            contract["createdAt"] = _now_iso()
            contract_digest = _digest(contract)
            events: list[dict[str, Any]] = []
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "loop-started",
                {
                    "contractDigest": contract_digest,
                    "executionMode": contract["executionMode"],
                    "autonomyLevel": contract["autonomyLevel"],
                    "riskTier": contract["riskTier"],
                },
            )
            snapshot = {
                "schemaVersion": LOOP_SNAPSHOT_SCHEMA,
                "loopId": loop_id,
                "status": "active",
                "decision": "continue",
                "contractDigest": contract_digest,
                "contractRevision": 1,
                "startedAt": contract["createdAt"],
                "updatedAt": event["occurredAt"],
                "iteration": 0,
                "noProgressCount": 0,
                "failureRepeatCount": 0,
                "lastFailureSignatureDigest": None,
                "sameBlockerCount": 0,
                "lastBlockerDigest": None,
                "fingerprintHistory": [subject["projectFingerprint"]],
                "currentFingerprint": subject["projectFingerprint"],
                "criteria": [
                    {"id": item["id"], "satisfied": False, "evidence": []}
                    for item in contract["acceptanceCriteria"]
                ],
                "completionApprovals": {},
                "circuitBreaker": None,
                "latestEventHash": event["eventHash"],
                "eventSequence": event["sequence"],
            }
            self._prepare_snapshot(snapshot, event)
            if contract["autonomyLevel"] in WRITE_AUTONOMY:
                self._set_active(loop_id)
            try:
                self._commit_state(loop_dir, contract, snapshot, events)
            except Exception:
                self._release_active(loop_id)
                raise
            _atomic_json(loop_dir / "project.json", {"gitRoot": str(self.project_root)})
            self._set_latest(loop_id)
            return self._public(contract, snapshot)

    def _public(self, contract: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
        satisfied = [item["id"] for item in snapshot.get("criteria", []) if item.get("satisfied")]
        return {
            "schemaVersion": LOOP_STATUS_SCHEMA,
            "loopId": snapshot["loopId"],
            "status": snapshot["status"],
            "decision": snapshot["decision"],
            "goal": contract["goal"],
            "executionMode": contract["executionMode"],
            "autonomyLevel": contract["autonomyLevel"],
            "riskTier": contract["riskTier"],
            "contractRevision": contract["revision"],
            "contractDigest": snapshot["contractDigest"],
            "baselineCommit": contract["project"]["baselineCommit"],
            "baselineFingerprint": contract["project"]["baselineFingerprint"],
            "policyDigest": contract["policy"]["digest"],
            "contractToolVersion": contract["policy"].get("toolVersion"),
            "acceptanceCriteria": contract["acceptanceCriteria"],
            "allowedPaths": contract["allowedPaths"],
            "iteration": snapshot["iteration"],
            "currentFingerprint": snapshot.get("currentFingerprint"),
            "limits": contract["limits"],
            "criteria": snapshot["criteria"],
            "satisfiedCriteria": satisfied,
            "remainingCriteria": [
                item["id"] for item in snapshot.get("criteria", []) if not item.get("satisfied")
            ],
            "circuitBreaker": snapshot.get("circuitBreaker"),
            "sameBlockerCount": snapshot.get("sameBlockerCount", 0),
            "goalBlockedEligible": False,
            "goalBlockedRule": (
                "Only Codex Goal mode may mark blocked, and only after the same blocker recurs "
                "for three consecutive goal turns. MCP checkpoint counts are advisory, not goal turns."
            ),
            "statePath": str(self._loop_dir(snapshot["loopId"])),
            "latestEventHash": snapshot["latestEventHash"],
            "updatedAt": snapshot["updatedAt"],
        }

    def status(self, loop_id: Optional[str] = None) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            selected = loop_id or self._active_loop() or self._latest_loop()
            if not selected:
                raise LoopError("No active or previous JStack loop exists for this repository.")
            _, contract, snapshot, _ = self._load(selected)
            return self._public(contract, snapshot)

    @staticmethod
    def _evaluate_criteria(
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        evidence: dict[str, Any],
    ) -> list[dict[str, Any]]:
        qa = {item.get("commandKey"): item for item in evidence.get("qa", [])}
        security = evidence.get("security")
        audits = evidence.get("audit", [])
        review = evidence.get("review")
        artifacts = {item.get("path"): item for item in evidence.get("artifacts", [])}
        approvals = snapshot.get("completionApprovals", {})
        results: list[dict[str, Any]] = []
        for criterion in contract["acceptanceCriteria"]:
            verifier = criterion["verifier"]
            verifier_type = verifier["type"]
            matched: list[dict[str, Any]] = []
            if (
                verifier_type == "qa"
                and verifier["commandKey"] in qa
                and qa[verifier["commandKey"]].get("passed") is True
            ):
                matched = [qa[verifier["commandKey"]]]
            elif verifier_type == "security" and security and security.get("passed") is True:
                matched = [security]
            elif verifier_type == "audit":
                matched = [
                    item
                    for item in audits
                    if item.get("passed") is True and item.get("profile") == verifier["profile"]
                ]
            elif verifier_type == "review" and review and review.get("passed") is True:
                matched = [review]
            elif verifier_type == "artifact":
                artifact = artifacts.get(verifier["path"])
                if artifact and artifact.get("exists") is True:
                    expected = verifier.get("sha256")
                    if not expected or artifact.get("sha256") == expected:
                        matched = [artifact]
            elif verifier_type == "human" and verifier["approvalKey"] in approvals:
                matched = [
                    {
                        "type": "human-approval-reference",
                        "approvalKey": verifier["approvalKey"],
                        "referenceDigest": _digest(approvals[verifier["approvalKey"]]),
                    }
                ]
            results.append(
                {
                    "id": criterion["id"],
                    "satisfied": bool(matched),
                    "evidence": matched,
                }
            )
        return results

    @staticmethod
    def _scope_violations(
        contract: dict[str, Any],
        changed_files: list[str],
        current_fingerprint: str,
    ) -> list[str]:
        allowed = contract["allowedPaths"]
        if contract["autonomyLevel"] not in WRITE_AUTONOMY:
            if current_fingerprint == contract["project"]["baselineFingerprint"]:
                return []
            return changed_files or ["<project-state-changed>"]
        return [
            path
            for path in changed_files
            if not any(_path_matches_pattern(path, pattern) for pattern in allowed)
        ]

    def checkpoint(
        self,
        loop_id: str,
        *,
        expected_contract_digest: str,
        subject: dict[str, Any],
        policy_digest: str,
        changed_files: list[str],
        protected_files: list[str],
        evidence: dict[str, Any],
        summary: str,
        failure_signature: Optional[str],
        blocker: Optional[str],
    ) -> dict[str, Any]:
        summary = _text(summary, "iteration_summary", maximum=MAX_SUMMARY_CHARS)
        failure = _text(
            failure_signature or "", "failure_signature", maximum=500, required=False
        ) or None
        blocker_text = _text(blocker or "", "blocker", maximum=1000, required=False) or None
        with _DirectoryLock(self.lock_path):
            loop_dir, contract, snapshot, events = self._load(loop_id)
            if snapshot["status"] in TERMINAL_STATUSES:
                raise LoopError(f"Loop is already terminal: {snapshot['status']}")
            if snapshot["status"] == "needs_approval":
                raise LoopError(
                    "Loop is paused by a circuit breaker; record an approved contract revision before checkpointing again."
                )
            if snapshot["contractDigest"] != expected_contract_digest:
                raise LoopError("Loop contract changed during evidence collection; restart the checkpoint.")
            policy_changed = policy_digest != contract["policy"]["digest"]
            tool_version_changed = (
                subject.get("toolVersion") != contract["policy"].get("toolVersion")
            )
            scope_violations = self._scope_violations(
                contract, changed_files, subject["projectFingerprint"]
            )
            changed_limit = len(changed_files) > contract["limits"]["maxChangedFiles"]
            unapproved_protected = bool(protected_files) and not contract["approvals"].get("protectedPaths")
            hidden_index_flags = (
                list(subject.get("hiddenIndexFlags") or [])
                if contract["autonomyLevel"] in WRITE_AUTONOMY
                else []
            )

            previous_criteria = snapshot.get("criteria", [])
            previous_satisfied = sum(1 for item in previous_criteria if item.get("satisfied"))
            criteria = self._evaluate_criteria(contract, snapshot, evidence)
            satisfied = sum(1 for item in criteria if item.get("satisfied"))
            current_fingerprint = subject["projectFingerprint"]
            history = list(snapshot.get("fingerprintHistory", []))
            previous_fingerprint = snapshot.get("currentFingerprint")
            progressed = satisfied > previous_satisfied or current_fingerprint != previous_fingerprint
            no_progress = 0 if progressed else int(snapshot.get("noProgressCount", 0)) + 1
            oscillating = (
                current_fingerprint != previous_fingerprint
                and current_fingerprint in history[-6:]
            )
            history.append(current_fingerprint)
            history = history[-12:]

            failure_digest = _digest(failure) if failure else None
            blocker_digest = _digest(blocker_text) if blocker_text else None
            if failure:
                repeats = (
                    int(snapshot.get("failureRepeatCount", 0)) + 1
                    if snapshot.get("lastFailureSignatureDigest") == failure_digest
                    else 1
                )
            else:
                repeats = 0
            if blocker_text:
                blocker_count = (
                    int(snapshot.get("sameBlockerCount", 0)) + 1
                    if snapshot.get("lastBlockerDigest") == blocker_digest
                    else 1
                )
            else:
                blocker_count = 0

            iteration = int(snapshot.get("iteration", 0)) + 1
            elapsed_minutes = int(
                max(0, (_now() - _parse_time(snapshot["startedAt"], "startedAt")).total_seconds()) // 60
            )
            limits = contract["limits"]
            circuit: Optional[dict[str, Any]] = None
            context_reasons: list[str] = []
            if policy_changed:
                context_reasons.append("The enterprise policy digest changed after contract creation.")
            if tool_version_changed:
                context_reasons.append("The JStack tool version changed after contract creation.")
            policy_reasons: list[str] = []
            if scope_violations:
                policy_reasons.append("Changed files escaped the approved path scope.")
            if changed_limit:
                policy_reasons.append("The changed-file limit was exceeded.")
            if unapproved_protected:
                policy_reasons.append("Protected paths changed without a recorded approval reference.")
            if hidden_index_flags:
                policy_reasons.append(
                    "Git hidden-index flags appeared after the clean write-loop baseline."
                )

            all_satisfied = bool(criteria) and satisfied == len(criteria)
            if policy_reasons:
                decision = "policy_stop"
                status = "stopped"
                circuit = {"reason": "policy", "details": policy_reasons}
            elif context_reasons:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {
                    "reason": "contract_context_changed",
                    "details": context_reasons,
                }
            elif blocker_text:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "reported_blocker", "blockerDigest": blocker_digest}
            elif all_satisfied:
                decision = "ready_to_finalize"
                status = "active"
            elif iteration >= limits["maxIterations"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "max_iterations", "limit": limits["maxIterations"]}
            elif elapsed_minutes >= limits["maxElapsedMinutes"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "max_elapsed", "limitMinutes": limits["maxElapsedMinutes"]}
            elif repeats >= limits["maxRepeatedFailure"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "repeated_failure", "signatureDigest": failure_digest}
            elif no_progress >= limits["maxNoProgress"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "no_progress", "count": no_progress}
            elif oscillating:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "oscillation", "fingerprint": current_fingerprint}
            else:
                decision = "continue"
                status = "active"

            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "checkpoint",
                {
                    "iteration": iteration,
                    "summary": summary,
                    "projectFingerprint": current_fingerprint,
                    "changedFiles": changed_files,
                    "protectedFiles": protected_files,
                    "scopeViolations": scope_violations,
                    "criteria": criteria,
                    "evidenceDigest": _digest(evidence),
                    "failureSignatureDigest": failure_digest,
                    "blockerDigest": blocker_digest,
                    "decision": decision,
                    "circuitBreaker": circuit,
                },
            )
            snapshot.update(
                {
                    "status": status,
                    "decision": decision,
                    "iteration": iteration,
                    "criteria": criteria,
                    "noProgressCount": no_progress,
                    "failureRepeatCount": repeats,
                    "lastFailureSignatureDigest": failure_digest,
                    "sameBlockerCount": blocker_count,
                    "lastBlockerDigest": blocker_digest,
                    "fingerprintHistory": history,
                    "currentFingerprint": current_fingerprint,
                    "circuitBreaker": circuit,
                }
            )
            self._prepare_snapshot(snapshot, event)
            self._commit_state(loop_dir, contract, snapshot, events)
            if status == "stopped":
                self._release_active(loop_id)
            result = self._public(contract, snapshot)
            result.update(
                {
                    "scopeViolations": scope_violations,
                    "protectedFiles": protected_files,
                    "changedFiles": changed_files,
                    "policyChanged": policy_changed,
                    "toolVersionChanged": tool_version_changed,
                    "hiddenIndexFlagCount": len(hidden_index_flags),
                    "invalidEvidence": evidence.get("invalid", []),
                    "sameBlockerCheckpointCount": blocker_count,
                    "goalBlockedEligible": False,
                }
            )
            return result

    def revise(
        self,
        loop_id: str,
        args: dict[str, Any],
        *,
        subject: dict[str, Any],
        worktree: bool,
        policy_source: Optional[str],
        policy_digest: str,
    ) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            loop_dir, old, snapshot, events = self._load(loop_id)
            if snapshot["status"] in TERMINAL_STATUSES:
                raise LoopError("Terminal loops cannot be revised; start a new loop.")
            if int(old.get("revision", 0)) >= MAX_CONTRACT_REVISIONS:
                raise LoopError(
                    "Loop contract revision capacity reached; stop this loop and start a continuation contract."
                )
            new_args = {
                "goal": args.get("goal", old["goal"]),
                "execution_mode": args.get("execution_mode", old["executionMode"]),
                "autonomy_level": args.get("autonomy_level", old["autonomyLevel"]),
                "risk_tier": args.get("risk_tier", old["riskTier"]),
                "acceptance_criteria": args.get("acceptance_criteria", old["acceptanceCriteria"]),
                "non_goals": args.get("non_goals", old["nonGoals"]),
                "allowed_paths": args.get("allowed_paths", old["allowedPaths"]),
                "blocked_actions": args.get("blocked_actions", old["blockedActions"]),
                "limits": args.get("limits") or {
                    "max_iterations": old["limits"]["maxIterations"],
                    "max_no_progress": old["limits"]["maxNoProgress"],
                    "max_repeated_failure": old["limits"]["maxRepeatedFailure"],
                    "max_elapsed_minutes": old["limits"]["maxElapsedMinutes"],
                    "max_changed_files": old["limits"]["maxChangedFiles"],
                },
                "token_budget": old.get("tokenBudget"),
                "mode_approval_reference": args.get("mode_approval_reference") or old["approvals"].get("mode"),
                "autonomy_approval_reference": args.get("autonomy_approval_reference") or old["approvals"].get("autonomy"),
                "risk_approval_reference": args.get("risk_approval_reference") or old["approvals"].get("risk"),
                "protected_path_approval": args.get("protected_path_approval") or old["approvals"].get("protectedPaths"),
            }
            new = _normalize_contract_input(
                new_args,
                project_root=str(self.project_root),
                subject=subject,
                worktree=worktree,
                policy_source=policy_source,
                policy_digest=policy_digest,
                require_clean_start=False,
            )
            new["project"] = {
                **old["project"],
                "worktreeAttested": worktree,
            }
            if (
                old["autonomyLevel"] not in WRITE_AUTONOMY
                and new["autonomyLevel"] in WRITE_AUTONOMY
                and subject.get("clean") is not True
            ):
                raise LoopError("Entering write-capable autonomy requires a clean Git worktree.")
            changed_fields = [
                field
                for field in (
                    "goal",
                    "nonGoals",
                    "executionMode",
                    "autonomyLevel",
                    "riskTier",
                    "acceptanceCriteria",
                    "allowedPaths",
                    "blockedActions",
                    "requireChange",
                    "limits",
                    "tokenBudget",
                    "approvals",
                    "policy",
                )
                if new[field] != old[field]
            ]
            approval_updates = _normalize_approvals(args.get("approval_updates"))
            human_approval_keys = {
                item["verifier"]["approvalKey"]
                for item in new["acceptanceCriteria"]
                if item["verifier"]["type"] == "human"
            }
            unknown_approval_keys = sorted(set(approval_updates) - human_approval_keys)
            if unknown_approval_keys:
                raise LoopError(
                    "approval_updates contains keys that are not human acceptance criteria: "
                    + ", ".join(unknown_approval_keys)
                )
            approval_reference = _text(
                args.get("revision_approval_reference") or "",
                "revision_approval_reference",
                maximum=500,
                required=bool(changed_fields),
            )
            if not changed_fields and not approval_updates and not approval_reference:
                raise LoopError(
                    "Loop revision did not change the contract, add a human approval, or record an explicit resume approval."
                )
            if (
                snapshot["status"] == "needs_approval"
                and not approval_updates
                and not approval_reference
            ):
                raise LoopError("A paused loop requires an explicit approval reference before resuming.")
            new["loopId"] = loop_id
            new["createdAt"] = old["createdAt"]
            new["revision"] = int(old["revision"]) + 1
            new["revisedAt"] = _now_iso()
            new["revisionApprovalReference"] = approval_reference or None
            new_digest = _digest(new)
            acquired_write_lease = False
            if new["autonomyLevel"] in WRITE_AUTONOMY:
                active = self._active_loop()
                if active and active != loop_id:
                    raise LoopError(f"Write-capable loop {active} already owns this repository.")
                if active is None:
                    self._set_active(loop_id)
                    acquired_write_lease = True
            completion_approvals = (
                {}
                if changed_fields
                else {
                    key: value
                    for key, value in snapshot.get("completionApprovals", {}).items()
                    if key in human_approval_keys
                }
            )
            completion_approvals.update(approval_updates)
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "contract-revised",
                {
                    "oldContractDigest": snapshot["contractDigest"],
                    "newContractDigest": new_digest,
                    "changedFields": changed_fields,
                    "revisionApprovalDigest": _digest(approval_reference) if approval_reference else None,
                    "approvalKeysAdded": sorted(approval_updates),
                },
            )
            snapshot.update(
                {
                    "status": "active",
                    "decision": "continue",
                    "contractDigest": new_digest,
                    "contractRevision": new["revision"],
                    "criteria": [
                        {"id": item["id"], "satisfied": False, "evidence": []}
                        for item in new["acceptanceCriteria"]
                    ],
                    "completionApprovals": completion_approvals,
                    "noProgressCount": 0,
                    "failureRepeatCount": 0,
                    "lastFailureSignatureDigest": None,
                    "sameBlockerCount": 0,
                    "lastBlockerDigest": None,
                    "circuitBreaker": None,
                    "currentFingerprint": subject["projectFingerprint"],
                    "fingerprintHistory": [subject["projectFingerprint"]],
                }
            )
            self._prepare_snapshot(snapshot, event)
            try:
                self._commit_state(loop_dir, new, snapshot, events)
            except Exception:
                if acquired_write_lease:
                    self._release_active(loop_id)
                raise
            if new["autonomyLevel"] in WRITE_AUTONOMY:
                self._set_active(loop_id)
            else:
                self._release_active(loop_id)
            return self._public(new, snapshot)

    def stop(self, loop_id: str, reason: str) -> dict[str, Any]:
        reason = _text(reason, "reason", maximum=1000)
        with _DirectoryLock(self.lock_path):
            loop_dir, contract, snapshot, events = self._load(loop_id)
            if snapshot["status"] == "succeeded":
                raise LoopError("A succeeded loop cannot be stopped.")
            if snapshot["status"] == "stopped":
                return self._public(contract, snapshot)
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "loop-stopped",
                {"reason": reason},
            )
            snapshot.update(
                {
                    "status": "stopped",
                    "decision": "user_stop",
                    "circuitBreaker": {"reason": "user_stop", "detail": reason},
                }
            )
            self._prepare_snapshot(snapshot, event)
            self._commit_state(loop_dir, contract, snapshot, events)
            self._release_active(loop_id)
            return self._public(contract, snapshot)

    def finalize(
        self,
        loop_id: str,
        *,
        expected_contract_digest: str,
        subject: dict[str, Any],
        policy_digest: str,
        changed_files: list[str],
        protected_files: list[str],
        evidence: dict[str, Any],
        summary: str,
    ) -> dict[str, Any]:
        summary = _text(summary, "completion_summary", maximum=MAX_SUMMARY_CHARS)
        with _DirectoryLock(self.lock_path):
            loop_dir, contract, snapshot, events = self._load(loop_id)
            if snapshot["contractDigest"] != expected_contract_digest:
                raise LoopError("Loop contract changed during evidence collection; restart finalization.")
            if snapshot["status"] == "stopped":
                raise LoopError("A stopped loop cannot be finalized.")
            if snapshot["status"] == "needs_approval":
                raise LoopError(
                    "Loop is paused by a circuit breaker; record an approved contract revision before finalizing."
                )
            if snapshot["status"] == "succeeded":
                if snapshot.get("currentFingerprint") != subject["projectFingerprint"]:
                    raise LoopError("Succeeded loop state no longer matches the repository; no receipt can be reissued.")
                if policy_digest != contract["policy"]["digest"]:
                    raise LoopError("Enterprise policy changed after completion; no receipt can be reissued.")
                if subject.get("toolVersion") != contract["policy"].get("toolVersion"):
                    raise LoopError("JStack tool version changed after completion; no receipt can be reissued.")
                violations = self._scope_violations(
                    contract, changed_files, subject["projectFingerprint"]
                )
                if violations:
                    raise LoopError("Final changed files escape the approved path scope: " + ", ".join(violations))
                if len(changed_files) > contract["limits"]["maxChangedFiles"]:
                    raise LoopError("Final changed-file count exceeds the loop contract limit.")
                if contract.get("requireChange") is True and not changed_files:
                    raise LoopError("Write-capable loop completion requires at least one in-scope changed file.")
                if protected_files and not contract["approvals"].get("protectedPaths"):
                    raise LoopError("Protected final changes require a recorded approval reference.")
                if (
                    contract["autonomyLevel"] in WRITE_AUTONOMY
                    and subject.get("hiddenIndexFlags")
                ):
                    raise LoopError("Git hidden-index flags invalidate write-loop completion evidence.")
                criteria = self._evaluate_criteria(contract, snapshot, evidence)
                remaining = [item["id"] for item in criteria if not item["satisfied"]]
                if remaining:
                    raise LoopError("Current evidence no longer satisfies completion: " + ", ".join(remaining))
                evidence_digest = _digest(evidence)
                event = self._append_event(
                    loop_dir,
                    events,
                    loop_id,
                    "completion-revalidated",
                    {
                        "projectFingerprint": subject["projectFingerprint"],
                        "criteria": criteria,
                        "evidenceDigest": evidence_digest,
                    },
                )
                snapshot.update(
                    {
                        "criteria": criteria,
                        "completionEvidenceDigest": evidence_digest,
                        "currentFingerprint": subject["projectFingerprint"],
                    }
                )
                self._prepare_snapshot(snapshot, event)
                self._commit_state(loop_dir, contract, snapshot, events)
                result = self._public(contract, snapshot)
                result["completionEvidenceDigest"] = evidence_digest
                result["changedFiles"] = changed_files
                result["protectedFiles"] = protected_files
                result["reissued"] = True
                return result
            if policy_digest != contract["policy"]["digest"]:
                raise LoopError("Enterprise policy changed after contract creation; revise the loop before finalizing.")
            if subject.get("toolVersion") != contract["policy"].get("toolVersion"):
                raise LoopError("JStack tool version changed after contract creation; revise the loop before finalizing.")
            violations = self._scope_violations(
                contract, changed_files, subject["projectFingerprint"]
            )
            if violations:
                raise LoopError("Final changed files escape the approved path scope: " + ", ".join(violations))
            if len(changed_files) > contract["limits"]["maxChangedFiles"]:
                raise LoopError("Final changed-file count exceeds the loop contract limit.")
            if contract.get("requireChange") is True and not changed_files:
                raise LoopError("Write-capable loop completion requires at least one in-scope changed file.")
            if protected_files and not contract["approvals"].get("protectedPaths"):
                raise LoopError("Protected final changes require a recorded approval reference.")
            if (
                contract["autonomyLevel"] in WRITE_AUTONOMY
                and subject.get("hiddenIndexFlags")
            ):
                raise LoopError("Git hidden-index flags invalidate write-loop completion evidence.")
            criteria = self._evaluate_criteria(contract, snapshot, evidence)
            remaining = [item["id"] for item in criteria if not item["satisfied"]]
            if remaining:
                raise LoopError("Loop acceptance criteria are not satisfied: " + ", ".join(remaining))
            evidence_digest = _digest(evidence)
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "loop-succeeded",
                {
                    "summary": summary,
                    "projectFingerprint": subject["projectFingerprint"],
                    "changedFiles": changed_files,
                    "criteria": criteria,
                    "evidenceDigest": evidence_digest,
                },
            )
            snapshot.update(
                {
                    "status": "succeeded",
                    "decision": "complete",
                    "criteria": criteria,
                    "currentFingerprint": subject["projectFingerprint"],
                    "completionEvidenceDigest": evidence_digest,
                    "completionSummary": summary,
                    "circuitBreaker": None,
                }
            )
            self._prepare_snapshot(snapshot, event)
            self._commit_state(loop_dir, contract, snapshot, events)
            self._release_active(loop_id)
            result = self._public(contract, snapshot)
            result.update(
                {
                    "completionEvidenceDigest": evidence_digest,
                    "changedFiles": changed_files,
                    "protectedFiles": protected_files,
                    "reissued": False,
                }
            )
            return result
