from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.proof_plane.attempt_bundle import (
    ARTIFACT_ENTRY_NAMES,
    attempt_bundle_paths,
    run_slug,
    validate_attempt_bundle,
)
from tools.proof_plane.broker import broker_config_digest
from tools.proof_plane.common import (
    ProofPlaneError,
    advance_ledger_anchor,
    append_ledger_event,
    canonical_bytes,
    canonical_digest,
    create_ledger_anchor,
)
from tools.proof_plane.runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _write_canonical(path: Path, value: dict) -> None:
    _write_private(path, canonical_bytes(value) + b"\n")


class AttemptBundleFixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.chmod(0o700)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.attempts = self.private / "attempts"
        self.ledgers = self.private / "ledgers"
        self.anchors = self.private / "anchors"
        for directory in (self.attempts, self.ledgers, self.anchors):
            directory.mkdir(mode=0o700)
        self.runtime = self.root / "container"
        _write_private(self.runtime, b"#!/bin/sh\nexit 0\n")
        self.runtime.chmod(0o700)
        self.run_id = "python-api-seeded-defect:controlled:r1:plain"
        self.paths = attempt_bundle_paths(self.private.resolve(), self.run_id)
        self.expected_run = {
            "runId": self.run_id,
            "baselineCommit": "a" * 40,
            "taskId": "python-api-seeded-defect",
        }
        self.start_bindings = {
            "registrationSha256": _digest("registration"),
            "scheduleSha256": _digest("schedule"),
            "expectedRunSetSha256": _digest("expected-run-set"),
            "preflightReceiptSha256": _digest("preflight"),
            "qualificationReceiptSetSha256": _digest("qualification"),
        }
        self.paths.artifact_root.mkdir(mode=0o700)
        self.paths.source_root.mkdir(mode=0o700)
        self.paths.codex_home.mkdir(mode=0o700)
        _write_private(self.paths.ledger, b"")
        self.anchor = create_ledger_anchor(
            self.paths.ledger_anchor,
            self.paths.ledger,
            expected_record_count=0,
            expected_head_sha256="0" * 64,
        )
        self.prompt = b"Implement the frozen task.\n"
        self.transcript = b'{"type":"turn.completed"}\n'
        self.stderr = b""
        self.patch = b"diff --git a/a b/a\n"
        for path, payload in (
            (self.paths.prompt, self.prompt),
            (self.paths.transcript, self.transcript),
            (self.paths.stderr, self.stderr),
            (self.paths.patch, self.patch),
        ):
            _write_private(path, payload)

        broker = {
            "schemaVersion": "jstack.proof-broker.config.v1",
            "studyId": "beta1-study",
            "runId": self.run_id,
            "registrationSha256": self.start_bindings["registrationSha256"],
            "configSha256": "0" * 64,
            "runtimeCommand": str(self.runtime.resolve()),
            "isolationCommand": "/usr/bin/bwrap",
            "containerId": "jstack-proof-attempt-1",
            "workspaceRoot": "/workspace",
            "user": "501:20",
            "toolCallLimit": 8,
            "commandTimeoutSeconds": 30,
            "outputByteLimit": 1_000_000,
            "ledgerPath": str(self.paths.ledger),
        }
        broker["configSha256"] = broker_config_digest(broker)
        self.broker = broker
        _write_canonical(self.paths.broker_config, broker)

        started = "2026-08-13T10:00:00Z"
        finished = "2026-08-13T10:00:01Z"
        model = {
            "schemaVersion": "jstack.eval.model-result.v1",
            "runId": self.run_id,
            "status": "completed",
            "reasonCode": "completed",
            "startedAt": started,
            "finishedAt": finished,
            "wallClockSeconds": 1.0,
            "complete": True,
            "truncated": False,
            "returnCode": 0,
            "tokenCount": 12,
            "usage": {"inputTokens": 10, "cachedInputTokens": 2, "outputTokens": 2},
            "eventCount": 3,
            "threadIdSha256": _digest("thread"),
            "terminalErrorSha256": None,
            "diagnosticSha256": None,
            "finalMessage": "Implemented and verified.",
            "promptSha256": hashlib.sha256(self.prompt).hexdigest(),
            "commandSha256": _digest("command"),
            "brokerConfigSha256": broker["configSha256"],
            "modelInstanceIdSha256": _digest("model-instance"),
            "containerStarted": True,
            "modelInstanceDestroyed": True,
            "sourceArchiveSha256": _digest("source-archive"),
            "sourceContentSha256": _digest("source-content"),
            "baselineCommit": self.expected_run["baselineCommit"],
            "workspaceContentSha256": _digest("workspace-content"),
            "patchCaptureSucceeded": True,
            "transcriptSha256": hashlib.sha256(self.transcript).hexdigest(),
            "stderrSha256": hashlib.sha256(self.stderr).hexdigest(),
            "patchSha256": hashlib.sha256(self.patch).hexdigest(),
            "runtimeTcbObservation": {
                "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
                "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
                "expectedSha256": _digest("runtime-tcb"),
                "beforeSha256": _digest("runtime-tcb"),
                "afterSha256": _digest("runtime-tcb"),
            },
            "imageStoreObservation": {
                "expectedSha256": _digest("image-store"),
                "beforeSha256": _digest("image-store"),
                "afterSha256": _digest("image-store"),
            },
            "containerInvocationSha256": _digest("container-invocation"),
        }
        self.model = model
        _write_canonical(self.paths.model_result, model)

        self.reservation_entry_sha256 = _digest("controller-reservation-entry")
        self.trusted_attempt_plan = {
            "promptSha256": model["promptSha256"],
            "brokerConfigSha256": model["brokerConfigSha256"],
            "commandSha256": model["commandSha256"],
            "modelInstanceIdSha256": model["modelInstanceIdSha256"],
            "sourceArchiveSha256": model["sourceArchiveSha256"],
            "sourceContentSha256": model["sourceContentSha256"],
            "baselineCommit": model["baselineCommit"],
            "baselineResultSha256": _digest("baseline-result"),
            "runtimeTcbSha256": model["runtimeTcbObservation"]["expectedSha256"],
            "imageStoreObservationSha256": model["imageStoreObservation"][
                "expectedSha256"
            ],
        }

        start = {
            "schemaVersion": "jstack.eval.primary-attempt-start.v1",
            "runId": self.run_id,
            "ordinal": 1,
            "startedAt": started,
            "reservationEntrySha256": self.reservation_entry_sha256,
            **self.start_bindings,
            "expectedRunSha256": canonical_digest(self.expected_run),
            "ledgerPathSha256": hashlib.sha256(
                str(self.paths.ledger).encode("utf-8")
            ).hexdigest(),
            "anchorPathSha256": hashlib.sha256(
                str(self.paths.ledger_anchor).encode("utf-8")
            ).hexdigest(),
            "genesisAnchorSha256": self.anchor["anchorSha256"],
            "trustedAttemptPlan": self.trusted_attempt_plan,
            "trustedAttemptPlanSha256": canonical_digest(self.trusted_attempt_plan),
            "retryPolicy": "one-scored-invocation-no-retry",
        }
        self.start = start
        _write_canonical(self.paths.start_receipt, start)
        terminal = {
            "schemaVersion": "jstack.eval.primary-attempt-terminal.v1",
            "runId": self.run_id,
            "recordedAt": "2026-08-13T10:00:02Z",
            "startReceiptSha256": hashlib.sha256(
                self.paths.start_receipt.read_bytes()
            ).hexdigest(),
            "ledgerSha256": hashlib.sha256(b"").hexdigest(),
            "ledgerRecordCount": 0,
            "ledgerHeadSha256": "0" * 64,
            "ledgerAnchorSha256": self.anchor["anchorSha256"],
            "ledgerAnchorRevision": 0,
            "terminal": {
                "status": model["status"],
                "modelInstanceIdSha256": model["modelInstanceIdSha256"],
                "modelResultSha256": hashlib.sha256(
                    self.paths.model_result.read_bytes()
                ).hexdigest(),
                "transcriptSha256": model["transcriptSha256"],
                "patchSha256": model["patchSha256"],
            },
        }
        self.terminal = terminal
        _write_canonical(self.paths.terminal_receipt, terminal)

    def validate(self):
        return validate_attempt_bundle(
            self.private.resolve(),
            self.run_id,
            expected_run=self.expected_run,
            immutable_start_bindings=self.start_bindings,
            reservation_entry_sha256=self.reservation_entry_sha256,
            expected_trusted_attempt_plan=self.trusted_attempt_plan,
            expected_broker_config_sha256=self.broker["configSha256"],
            expected_study_id=self.broker["studyId"],
        )

    def rewrite_model_and_terminal(self, model: dict) -> None:
        self.model = model
        _write_canonical(self.paths.model_result, model)
        terminal = copy.deepcopy(self.terminal)
        terminal["terminal"]["status"] = model["status"]
        terminal["terminal"]["modelInstanceIdSha256"] = model[
            "modelInstanceIdSha256"
        ]
        terminal["terminal"]["modelResultSha256"] = hashlib.sha256(
            self.paths.model_result.read_bytes()
        ).hexdigest()
        terminal["terminal"]["transcriptSha256"] = model["transcriptSha256"]
        terminal["terminal"]["patchSha256"] = model["patchSha256"]
        self.terminal = terminal
        _write_canonical(self.paths.terminal_receipt, terminal)

    def advance_anchor(self) -> dict:
        append_ledger_event(self.paths.ledger, {"kind": "fixture-event"})
        prior = self.anchor
        self.anchor = advance_ledger_anchor(
            self.paths.ledger_anchor,
            self.paths.ledger,
            expected_record_count=prior["recordCount"],
            expected_head_sha256=prior["terminalHeadSha256"],
            expected_anchor_sha256=prior["anchorSha256"],
        )
        self.rebind_terminal_to_anchor()
        return self.anchor

    def rebind_terminal_to_anchor(self) -> None:
        terminal = copy.deepcopy(self.terminal)
        terminal["ledgerSha256"] = hashlib.sha256(
            self.paths.ledger.read_bytes()
        ).hexdigest()
        terminal["ledgerRecordCount"] = self.anchor["recordCount"]
        terminal["ledgerHeadSha256"] = self.anchor["terminalHeadSha256"]
        terminal["ledgerAnchorSha256"] = self.anchor["anchorSha256"]
        terminal["ledgerAnchorRevision"] = self.anchor["revision"]
        self.terminal = terminal
        _write_canonical(self.paths.terminal_receipt, terminal)


@unittest.skipIf(os.name == "nt", "private-mode and symlink checks are POSIX-specific")
class AttemptBundleTests(unittest.TestCase):
    def fixture(self, temporary: str) -> AttemptBundleFixture:
        return AttemptBundleFixture(Path(temporary))

    def test_valid_bundle_uses_closed_deterministic_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            bundle = fixture.validate()
            self.assertEqual(bundle.run_id, fixture.run_id)
            self.assertEqual(bundle.slug, run_slug(fixture.run_id))
            self.assertEqual(bundle.paths.artifact_root, fixture.paths.artifact_root)
            self.assertEqual(bundle.model_result, fixture.model)
            self.assertEqual(bundle.broker_config, fixture.broker)
            self.assertEqual(bundle.trusted_attempt_plan, fixture.trusted_attempt_plan)
            self.assertEqual(
                bundle.artifact_sha256["patch"],
                hashlib.sha256(fixture.patch).hexdigest(),
            )
            self.assertEqual(
                {child.name for child in fixture.paths.artifact_root.iterdir()},
                ARTIFACT_ENTRY_NAMES,
            )

    def test_missing_artifact_root_or_required_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            for child in fixture.paths.artifact_root.iterdir():
                if child.is_dir():
                    child.rmdir()
                else:
                    child.unlink()
            fixture.paths.artifact_root.rmdir()
            with self.assertRaisesRegex(ProofPlaneError, "artifact root.*missing"):
                fixture.validate()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            fixture.paths.patch.unlink()
            with self.assertRaisesRegex(ProofPlaneError, "missing candidate.patch"):
                fixture.validate()

    def test_invented_digest_is_not_accepted_even_when_receipt_is_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            model = copy.deepcopy(fixture.model)
            model["promptSha256"] = _digest("invented-prompt")
            fixture.rewrite_model_and_terminal(model)
            with self.assertRaisesRegex(ProofPlaneError, "invented raw-artifact digest"):
                fixture.validate()

    def test_model_runtime_tcb_must_match_the_anchored_attempt_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            model = copy.deepcopy(fixture.model)
            substitute = _digest("substitute-runtime-tcb")
            for field in ("expectedSha256", "beforeSha256", "afterSha256"):
                model["runtimeTcbObservation"][field] = substitute
            fixture.rewrite_model_and_terminal(model)
            with self.assertRaisesRegex(ProofPlaneError, "trusted attempt plan"):
                fixture.validate()

    def test_model_image_store_must_match_the_anchored_attempt_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            model = copy.deepcopy(fixture.model)
            substitute = _digest("substitute-image-store")
            for field in ("expectedSha256", "beforeSha256", "afterSha256"):
                model["imageStoreObservation"][field] = substitute
            fixture.rewrite_model_and_terminal(model)
            with self.assertRaisesRegex(ProofPlaneError, "trusted attempt plan"):
                fixture.validate()

    def test_extra_entry_symlink_and_public_mode_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            _write_private(fixture.paths.artifact_root / "extra.txt", b"extra")
            with self.assertRaisesRegex(ProofPlaneError, "unexpected extra.txt"):
                fixture.validate()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            fixture.paths.patch.unlink()
            fixture.paths.patch.symlink_to(fixture.paths.prompt)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                fixture.validate()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            fixture.paths.prompt.chmod(0o644)
            with self.assertRaisesRegex(ProofPlaneError, "mode-0600"):
                fixture.validate()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            fixture.paths.artifact_root.chmod(0o755)
            with self.assertRaisesRegex(ProofPlaneError, "mode-0700"):
                fixture.validate()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            fixture.paths.prompt.write_bytes(b"p" * 1_000_001)
            fixture.paths.prompt.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "byte limit"):
                fixture.validate()

    def test_broker_and_model_json_must_be_canonical(self) -> None:
        for field in ("broker_config", "model_result"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(temporary)
                path = getattr(fixture.paths, field)
                value = fixture.broker if field == "broker_config" else fixture.model
                _write_private(path, (json.dumps(value, indent=2) + "\n").encode("utf-8"))
                with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                    fixture.validate()

    def test_terminal_and_immutable_start_field_mismatches_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            terminal = copy.deepcopy(fixture.terminal)
            terminal["terminal"]["modelInstanceIdSha256"] = _digest("substitute-instance")
            _write_canonical(fixture.paths.terminal_receipt, terminal)
            with self.assertRaisesRegex(ProofPlaneError, "terminal projection differs"):
                fixture.validate()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            bindings = dict(fixture.start_bindings)
            bindings["scheduleSha256"] = _digest("substitute-schedule")
            with self.assertRaisesRegex(ProofPlaneError, "immutable binding scheduleSha256"):
                validate_attempt_bundle(
                    fixture.private.resolve(),
                    fixture.run_id,
                    expected_run=fixture.expected_run,
                    immutable_start_bindings=bindings,
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            expected = dict(fixture.expected_run)
            expected["taskId"] = "substitute-task"
            with self.assertRaisesRegex(ProofPlaneError, "exact expected run"):
                validate_attempt_bundle(
                    fixture.private.resolve(),
                    fixture.run_id,
                    expected_run=expected,
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            with self.assertRaisesRegex(ProofPlaneError, "anchored reservation"):
                validate_attempt_bundle(
                    fixture.private.resolve(),
                    fixture.run_id,
                    reservation_entry_sha256=_digest("substitute-reservation"),
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            plan = dict(fixture.trusted_attempt_plan)
            plan["baselineResultSha256"] = _digest("substitute-baseline-result")
            with self.assertRaisesRegex(ProofPlaneError, "expected trusted plan"):
                validate_attempt_bundle(
                    fixture.private.resolve(),
                    fixture.run_id,
                    expected_trusted_attempt_plan=plan,
                )

    def test_anchor_must_retain_complete_ancestry_from_start_genesis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            fixture.advance_anchor()
            self.assertEqual(fixture.validate().artifact_sha256["ledger_anchor"], fixture.anchor["anchorSha256"])

            anchor = copy.deepcopy(fixture.anchor)
            anchor["previousAnchorSha256"] = _digest("substitute-genesis")
            body = {name: item for name, item in anchor.items() if name != "anchorSha256"}
            anchor["anchorSha256"] = canonical_digest(body)
            fixture.anchor = anchor
            _write_private(
                fixture.paths.ledger_anchor,
                (json.dumps(anchor, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
            fixture.rebind_terminal_to_anchor()
            with self.assertRaisesRegex(ProofPlaneError, "does not descend from genesis"):
                fixture.validate()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(temporary)
            prior = fixture.advance_anchor()
            anchor = copy.deepcopy(prior)
            anchor["revision"] = 2
            anchor["previousAnchorSha256"] = prior["anchorSha256"]
            body = {name: item for name, item in anchor.items() if name != "anchorSha256"}
            anchor["anchorSha256"] = canonical_digest(body)
            fixture.anchor = anchor
            _write_private(
                fixture.paths.ledger_anchor,
                (json.dumps(anchor, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
            fixture.rebind_terminal_to_anchor()
            with self.assertRaisesRegex(ProofPlaneError, "exceeds the retained ancestry"):
                fixture.validate()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
