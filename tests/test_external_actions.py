from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SIGNER_PATH = ROOT / "mcp" / "jstack" / "sign_external_action_authorization.py"
SPEC = importlib.util.spec_from_file_location("jstack_external_action_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def make_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "JStack Tests")
    (repo / "README.md").write_text("# Exact action test\n", encoding="utf-8")
    (repo / "jstack.enterprise.json").write_text(
        json.dumps({"schemaVersion": "jstack.enterprise.v1", "standard": "enterprise"})
        + "\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


class ExternalActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.repo = make_repo(self.base)
        self.key = "external-action-human-owned-test-key-000000000000"
        self.identity_path = self.base / "identities.json"
        self.identity_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "jstack.external-action.identity-config.v1",
                    "identities": {
                        "jay": {
                            "roles": sorted(
                                set(server.authorization_core.ACTION_ROLES.values())
                            ),
                            "hmacKeyEnv": "JSTACK_TEST_EXTERNAL_ACTION_KEY",
                        }
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.home_patch = mock.patch.object(server.Path, "home", return_value=self.home)
        self.env_patch = mock.patch.dict(
            os.environ,
            {
                server.EXTERNAL_ACTION_IDENTITY_CONFIG_ENV: str(self.identity_path),
                "JSTACK_TEST_EXTERNAL_ACTION_KEY": self.key,
            },
        )
        self.home_patch.start()
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.home_patch.stop()
        self.temporary.cleanup()

    def local_target(self, action: str = "commit") -> dict:
        return {
            "provider": "local-git",
            "owner": "local",
            "repository": self.repo.name,
            "visibility": "local-only",
            "remoteName": "not-applicable",
            "remoteUrl": "not-applicable",
            "branch": git(self.repo, "branch", "--show-current"),
            "tag": "v1.0.0" if action == "tag_create" else "not-applicable",
            "exactCommit": git(self.repo, "rev-parse", "HEAD"),
            "targetEnvironment": "local",
        }

    def external_target(self, action: str = "push") -> dict:
        return {
            "provider": "github",
            "owner": "example-owner",
            "repository": "repo",
            "visibility": "private",
            "remoteName": "origin",
            "remoteUrl": "https://github.com/example-owner/repo.git",
            "branch": "main",
            "tag": "v1.0.0" if action == "release_create" else "not-applicable",
            "exactCommit": git(self.repo, "rev-parse", "HEAD"),
            "targetEnvironment": "repository",
        }

    def sign(self, challenge: dict) -> str:
        encoded = challenge["encodedPayload"]
        signature = server._b64encode(
            hmac.new(self.key.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
        )
        return encoded + "." + signature

    def challenge(self, action: str = "commit", target: dict | None = None) -> dict:
        return server.tool_external_action_challenge(
            {
                "project_path": str(self.repo),
                "action": action,
                "target": target or self.local_target(action),
                "approver_id": "jay",
                "approval_reference": "Jay approved this displayed exact one-time action.",
                "valid_for_seconds": 300,
            }
        )

    def authorize(self, challenge: dict) -> dict:
        return server.tool_external_action_authorize(
            {
                "project_path": str(self.repo),
                "authorization_id": challenge["authorizationId"],
                "approval_attestation": self.sign(challenge),
            }
        )

    def observation(self, target: dict, *, exists: bool = True) -> dict:
        return {
            "target": target,
            "providerTargetExists": exists,
            "source": "fresh-provider-observation:test-fixture",
            "observedAt": server.now_iso(),
        }

    def test_commit_authorization_is_exact_short_lived_and_consumed_once(self) -> None:
        challenge = self.challenge()
        self.assertEqual(["commit"], challenge["challenge"]["actionSet"])
        self.assertIn(challenge["challengeDigest"], challenge["confirmationText"])
        grant = self.authorize(challenge)
        consumed = server.tool_external_action_consume(
            {
                "project_path": str(self.repo),
                "authorization_receipt": grant["authorizationReceipt"],
                "action": "commit",
                "operation_id": "commit-once-1",
                "observation": self.observation(grant["target"]),
            }
        )
        self.assertTrue(consumed["consumed"])
        self.assertEqual("commit", consumed["action"])
        with self.assertRaisesRegex(server.ToolError, "already consumed|replay"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "commit",
                    "operation_id": "commit-once-2",
                    "observation": self.observation(grant["target"]),
                }
            )

    def test_challenge_and_authorization_replay_are_rejected(self) -> None:
        challenge = self.challenge()
        self.authorize(challenge)
        with self.assertRaisesRegex(server.ToolError, "already resolved|replay"):
            self.authorize(challenge)

    def test_action_escalation_is_rejected_before_consumption(self) -> None:
        grant = self.authorize(self.challenge())
        with self.assertRaisesRegex(server.ToolError, "mismatched|escalated"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "push",
                    "operation_id": "escalation-1",
                    "observation": self.observation(grant["target"]),
                }
            )

    def test_worktree_drift_invalidates_signed_challenge(self) -> None:
        challenge = self.challenge()
        (self.repo / "README.md").write_text("changed after challenge\n", encoding="utf-8")
        with self.assertRaisesRegex(server.ToolError, "drifted"):
            self.authorize(challenge)

    def test_commit_and_branch_drift_after_authorization_invalidate_consumption(self) -> None:
        grant = self.authorize(self.challenge())
        git(self.repo, "checkout", "-b", "changed-branch")
        with self.assertRaisesRegex(
            server.ToolError, "stale|drifted|mismatched|current attached branch"
        ):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "commit",
                    "operation_id": "branch-drift-1",
                    "observation": self.observation(grant["target"]),
                }
            )

    def test_remote_drift_invalidates_signed_push_challenge(self) -> None:
        target = self.external_target()
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        challenge = self.challenge("push", target)
        git(self.repo, "remote", "set-url", "origin", "https://github.com/example-owner/other.git")
        with self.assertRaisesRegex(server.ToolError, "named local remote|drifted"):
            self.authorize(challenge)

    def test_distinct_push_url_cannot_hide_behind_matching_fetch_url(self) -> None:
        target = self.external_target()
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        git(
            self.repo,
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            "https://github.com/example-owner/other.git",
        )
        with self.assertRaisesRegex(server.ToolError, "authorized push URL"):
            self.challenge("push", target)

    def test_branch_push_requires_exact_local_branch_tip(self) -> None:
        target = self.external_target()
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        target["branch"] = "missing-branch"
        with self.assertRaisesRegex(server.ToolError, "exact local branch"):
            self.challenge("push", target)

    def test_tag_push_binds_exact_existing_local_tag_and_commit(self) -> None:
        target = self.external_target()
        target["tag"] = "v1.0.0"
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        with self.assertRaisesRegex(server.ToolError, "exact local tag"):
            self.challenge("push", target)

        git(self.repo, "tag", "-a", target["tag"], "-m", "release")
        challenge = self.challenge("push", target)
        self.assertEqual(target["tag"], challenge["challenge"]["target"]["tag"])

        (self.repo / "README.md").write_text(
            "# Exact action test\nnext release\n", encoding="utf-8"
        )
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "next")
        drifted = dict(target)
        drifted["exactCommit"] = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(server.ToolError, "exact local tag"):
            self.challenge("push", drifted)

    def test_remote_drift_after_authorization_invalidates_consumption(self) -> None:
        target = self.external_target()
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        grant = self.authorize(self.challenge("push", target))
        git(self.repo, "remote", "set-url", "origin", "https://github.com/example-owner/other.git")
        with self.assertRaisesRegex(server.ToolError, "named local remote|drifted|stale"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "push",
                    "operation_id": "remote-drift-2",
                    "observation": self.observation(target),
                }
            )

    def test_visibility_and_provider_observation_drift_fail_closed(self) -> None:
        target = self.external_target()
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        grant = self.authorize(self.challenge("push", target))
        changed = dict(target)
        changed["visibility"] = "public"
        with self.assertRaisesRegex(server.ToolError, "observation does not exactly match"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "push",
                    "operation_id": "visibility-drift-1",
                    "observation": self.observation(changed),
                }
            )

    def test_provider_owner_and_repository_must_match_remote_url(self) -> None:
        target = self.external_target()
        target["owner"] = "wrong-owner"
        git(self.repo, "remote", "add", "origin", target["remoteUrl"])
        with self.assertRaisesRegex(server.ToolError, "does not match"):
            self.challenge("push", target)

    def test_repository_creation_requires_absent_provider_target_observation(self) -> None:
        target = self.external_target("repository_create")
        challenge = self.challenge("repository_create", target)
        grant = self.authorize(challenge)
        with self.assertRaisesRegex(server.ToolError, "existence"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "repository_create",
                    "operation_id": "repo-create-1",
                    "observation": self.observation(target, exists=True),
                }
            )

    def test_ambiguous_and_multi_action_intents_are_rejected(self) -> None:
        target = self.local_target()
        target["branch"] = "*"
        with self.assertRaisesRegex(server.ToolError, "ambiguous|safe exact"):
            self.challenge("commit", target)
        issued = server.authorization_core.now()
        binding = server._external_action_binding(self.repo)
        payload = {
            "schemaVersion": server.authorization_core.ATTESTATION_SCHEMA,
            "authorizationId": "authorization-20260721T120000Z-abcdef123456",
            "actionSet": ["commit", "push"],
            "requiredRole": "source-owner",
            "target": self.local_target(),
            "binding": binding,
            "approverId": "jay",
            "approvalReferenceDigest": "a" * 64,
            "issuedAt": issued.isoformat(),
            "expiresAt": (issued + dt.timedelta(minutes=5)).isoformat(),
            "nonce": "b" * 32,
        }
        with self.assertRaisesRegex(
            server.authorization_core.AuthorizationError, "exactly one"
        ):
            server.authorization_core.validate_attestation_payload(payload)

    def test_expired_challenge_and_stale_observation_fail_closed(self) -> None:
        issued = server.authorization_core.now() - dt.timedelta(minutes=20)
        payload = server.authorization_core.create_attestation_payload(
            authorization_id="authorization-20260721T120000Z-abcdef123456",
            action="commit",
            target=self.local_target(),
            binding=server._external_action_binding(self.repo),
            approver_id="jay",
            approval_reference_digest="a" * 64,
            nonce="b" * 32,
            valid_for_seconds=300,
            issued_at=issued,
        )
        with self.assertRaisesRegex(
            server.authorization_core.AuthorizationError, "not currently valid"
        ):
            server.authorization_core.validate_attestation_payload(payload)

        grant = self.authorize(self.challenge())
        stale = self.observation(grant["target"])
        stale["observedAt"] = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)
        ).replace(microsecond=0).isoformat()
        with self.assertRaisesRegex(server.ToolError, "stale"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "commit",
                    "operation_id": "stale-observation-1",
                    "observation": stale,
                }
            )

    def test_policy_floor_cannot_disable_or_remove_protected_actions(self) -> None:
        (self.repo / "jstack.enterprise.json").write_text(
            json.dumps(
                {
                    "schemaVersion": "jstack.enterprise.v1",
                    "externalActions": {
                        "requireSignedAuthorization": False,
                        "oneActionPerAuthorization": False,
                        "protectedActions": ["push"],
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        policy = server.load_enterprise_policy(self.repo)["externalActions"]
        self.assertTrue(policy["requireSignedAuthorization"])
        self.assertTrue(policy["oneActionPerAuthorization"])
        self.assertEqual(set(server.authorization_core.ACTIONS), set(policy["protectedActions"]))

    def test_tampered_durable_state_fails_its_session_integrity_check(self) -> None:
        challenge = self.challenge()
        grant = self.authorize(challenge)
        state_files = list(
            (self.home / ".jstack" / "external-actions").rglob(
                challenge["authorizationId"] + ".json"
            )
        )
        state_path = next(path for path in state_files if path.parent.name == "authorizations")
        value = json.loads(state_path.read_text(encoding="utf-8"))
        value["target"]["visibility"] = "public"
        state_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(server.ToolError, "integrity"):
            server.tool_external_action_consume(
                {
                    "project_path": str(self.repo),
                    "authorization_receipt": grant["authorizationReceipt"],
                    "action": "commit",
                    "operation_id": "tamper-1",
                    "observation": self.observation(grant["target"]),
                }
            )

    def test_broad_goal_and_release_readiness_never_authorize_execution(self) -> None:
        policy = server.tool_policy_check(
            {
                "project_path": str(self.repo),
                "goal": "Implement and deploy wave B phases 2-4, then release it.",
                "explicit_release_requested": True,
                "target_environment": "production",
            }
        )
        self.assertFalse(policy["externalActionBoundary"]["authorizationRequestInGoal"])
        self.assertTrue(policy["externalActionBoundary"]["signedAuthorizationRequired"])

    def test_artifact_only_directories_cannot_create_authorizations(self) -> None:
        artifact = self.base / "artifact"
        artifact.mkdir()
        with self.assertRaisesRegex(server.ToolError, "require a git repository"):
            server.tool_external_action_challenge(
                {
                    "project_path": str(artifact),
                    "action": "commit",
                    "target": self.local_target(),
                    "approver_id": "jay",
                    "approval_reference": "Exact action approval.",
                }
            )

    def test_runtime_and_tool_inventory_publish_the_boundary(self) -> None:
        runtime = server.tool_runtime_status({"project_path": str(self.repo)})
        self.assertEqual("local-only", runtime["externalActionBoundary"]["defaultMode"])
        names = {item["name"] for item in server.tool_definitions()}
        self.assertEqual(50, len(names))
        self.assertTrue(
            {
                "jstack_external_action_challenge",
                "jstack_external_action_authorize",
                "jstack_external_action_consume",
            }.issubset(names)
        )
        definitions = {item["name"]: item for item in server.tool_definitions()}
        self.assertTrue(
            definitions["jstack_external_action_consume"]["annotations"][
                "destructiveHint"
            ]
        )

    def test_signer_requires_full_confirmation_digest(self) -> None:
        challenge = self.challenge()
        environment = {**os.environ, "JSTACK_TEST_EXTERNAL_ACTION_KEY": self.key}
        rejected = subprocess.run(
            [
                sys.executable,
                str(SIGNER_PATH),
                "--encoded-payload",
                challenge["encodedPayload"],
                "--key-env",
                "JSTACK_TEST_EXTERNAL_ACTION_KEY",
                "--approver-id",
                "jay",
                "--confirm-digest",
                "0" * 64,
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("does not match", rejected.stderr)
        accepted = subprocess.run(
            [
                sys.executable,
                str(SIGNER_PATH),
                "--encoded-payload",
                challenge["encodedPayload"],
                "--key-env",
                "JSTACK_TEST_EXTERNAL_ACTION_KEY",
                "--approver-id",
                "jay",
                "--confirm-digest",
                challenge["challengeDigest"],
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertEqual(challenge["encodedPayload"], accepted.stdout.strip().split(".", 1)[0])


if __name__ == "__main__":
    unittest.main()
