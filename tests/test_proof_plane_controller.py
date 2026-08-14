from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS
from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    file_digest,
    load_json,
)
from tools.proof_plane.controller import (
    ReservationHandle,
    StudyRunController,
    TrustedAttemptPlan,
)
from tools.proof_plane.grading import seal_expected_run_set


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_canonical(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(canonical_bytes(value) + b"\n")
    os.chmod(path, mode)


def _fixture_expected_runs() -> list[dict]:
    runs = []
    for kind_index, kind in enumerate(TASK_KINDS):
        for family_index, family in enumerate(TARGET_FAMILIES):
            task_number = kind_index * len(TARGET_FAMILIES) + family_index + 1
            task_id = "task-%02d" % task_number
            for mode in ("controlled", "operational"):
                for repetition in range(1, 4):
                    pair_id = "%s:%s:r%d" % (task_id, mode, repetition)
                    for condition in ("plain", "jstack"):
                        runs.append(
                            {
                                "runId": pair_id + ":" + condition,
                                "pairId": pair_id,
                                "taskId": task_id,
                                "taskDigest": _digest("task:" + task_id),
                                "family": family,
                                "taskKind": kind,
                                "condition": condition,
                                "mode": mode,
                                "repetition": repetition,
                                "evidenceClass": "public",
                                "hostSha256": _digest("host"),
                                "environmentSha256": _digest("environment:" + task_id),
                                "limitsSha256": _digest("limits:%s:%s" % (mode, condition)),
                                "baselineCommit": hashlib.sha1(task_id.encode("utf-8")).hexdigest(),
                                "hiddenTestBundleSha256": _digest("holdout:" + task_id),
                            }
                        )
    return sorted(runs, key=lambda item: item["runId"])


def _fixture_schedule(expected_runs: list[dict]) -> list[dict]:
    # The controller accepts the already frozen schedule; this deterministic
    # fixture intentionally differs from runId sorting to exercise ordinal use.
    ordered = list(reversed(expected_runs))
    return [
        {
            "ordinal": index,
            "runId": item["runId"],
            "pairId": item["pairId"],
            "family": item["family"],
        }
        for index, item in enumerate(ordered, 1)
    ]


def _fixture_attempt_plan(run_id: str, baseline_commit: str) -> TrustedAttemptPlan:
    return TrustedAttemptPlan(
        prompt_sha256=_digest("prompt:" + run_id),
        broker_config_sha256=_digest("broker:" + run_id),
        command_sha256=_digest("command:" + run_id),
        model_instance_id_sha256=_digest("model:" + run_id),
        source_archive_sha256=_digest("source-archive:" + run_id),
        source_content_sha256=_digest("source-content:" + run_id),
        baseline_commit=baseline_commit,
        baseline_result_sha256=_digest("baseline-result:" + run_id),
        runtime_tcb_sha256=_digest("runtime-tcb"),
        image_store_observation_sha256=_digest("image-store:" + run_id),
    )


def _reserve_in_process(
    private_root: str, expected_path: str, schedule: list[dict], queue
) -> None:
    try:
        controller = StudyRunController(
            private_root=Path(private_root),
            expected_run_set_path=Path(expected_path),
            schedule=schedule,
            max_parallel=2,
        )
        result = controller.reserve_next()
        queue.put(("ok", result and result["runId"]))
    except Exception as exc:  # pragma: no cover - surfaced in the parent assertion.
        queue.put(("error", repr(exc)))


def _begin_in_process(
    private_root: str,
    expected_path: str,
    schedule: list[dict],
    reservation: dict,
    plan: dict,
    queue,
) -> None:
    try:
        controller = StudyRunController(
            private_root=Path(private_root),
            expected_run_set_path=Path(expected_path),
            schedule=schedule,
            max_parallel=2,
        )
        result = controller.begin_reserved_attempt(
            reservation, plan, started_at="2026-08-13T00:10:00Z"
        )
        queue.put(("ok", str(result)))
    except Exception as exc:  # pragma: no cover - surfaced in the parent assertion.
        queue.put(("error", repr(exc)))


class ControllerFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.expected_runs = _fixture_expected_runs()
        self.schedule = _fixture_schedule(self.expected_runs)
        self.expected = seal_expected_run_set(
            study_id="beta1-controller-study",
            expected_runs=self.expected_runs,
            frozen_at="2026-08-13T00:00:00Z",
            registration_sha256=_digest("registration"),
            manifest_sha256=_digest("manifest"),
            schedule_sha256=canonical_digest(self.schedule),
            preflight_receipt_sha256=_digest("preflight"),
            preflight_receipt_raw_sha256=_digest("preflight-file"),
            registration_tag_object_sha1=hashlib.sha1(b"tag").hexdigest(),
            registration_commit_sha1=hashlib.sha1(b"commit").hexdigest(),
            harness_lock_sha256=_digest("harness"),
            qualification_receipt_set_sha256=_digest("qualification"),
            qualification_command_map_sha256=_digest("commands"),
            evidence_bindings_sha256=_digest("bindings"),
            runtime_tcb_sha256=_digest("runtime-tcb"),
            task_artifact_set_summary_sha256=_digest(
                "task-artifact-summary"
            ),
            task_artifact_set_summary_raw_sha256=_digest(
                "tas" "k-artifact-summary-raw"
            ),
        )
        self.expected_path = self.root / "expected-run-set.json"
        _write_canonical(self.expected_path, self.expected)
        self.controller = StudyRunController(
            private_root=self.root,
            expected_run_set_path=self.expected_path,
            schedule=self.schedule,
            max_parallel=2,
        )

    def close(self) -> None:
        self.temporary.cleanup()

    def paths(self, run_id: str) -> dict[str, Path]:
        return self.controller._attempt_paths(run_id)

    def write_attempt(
        self,
        run_id: str,
        ordinal: int,
        *,
        status: str = "completed",
        started_at: str = "2026-08-13T00:10:00Z",
        recorded_at: str = "2026-08-13T00:20:00Z",
    ) -> Path:
        paths = self.paths(run_id)
        expected_run = next(item for item in self.expected_runs if item["runId"] == run_id)
        active = next(
            item
            for item in self.controller.status()["active"]
            if item["runId"] == run_id
        )
        reservation = ReservationHandle.from_value(
            {
                "runId": run_id,
                "ordinal": ordinal,
                "reservedAt": active["reservedAt"],
                "reservationEntrySha256": active["reservationEntrySha256"],
            }
        )
        self.controller.begin_reserved_attempt(
            reservation,
            _fixture_attempt_plan(run_id, expected_run["baselineCommit"]),
            started_at=started_at,
        )
        anchor = load_json(paths["anchor"])
        terminal = {
            "schemaVersion": "jstack.eval.primary-attempt-terminal.v1",
            "runId": run_id,
            "recordedAt": recorded_at,
            "startReceiptSha256": file_digest(paths["start"]),
            "ledgerSha256": file_digest(paths["ledger"]),
            "ledgerRecordCount": 0,
            "ledgerHeadSha256": "0" * 64,
            "ledgerAnchorSha256": anchor["anchorSha256"],
            "ledgerAnchorRevision": 0,
            "terminal": {
                "status": status,
                "modelInstanceIdSha256": _digest("model:" + run_id),
                "modelResultSha256": _digest("result:" + run_id),
                "transcriptSha256": _digest("transcript:" + run_id),
                "patchSha256": _digest("patch:" + run_id),
            },
        }
        _write_canonical(paths["terminal"], terminal)
        return paths["terminal"]


class StudyRunControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ControllerFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_initialization_is_idempotent_and_input_bound(self) -> None:
        state = self.fixture.controller.initialize()
        self.assertEqual(state["journalRecordCount"], 1)
        self.assertEqual(self.fixture.controller.initialize(), state)
        self.assertEqual(state["nextPendingOrdinal"], 1)
        self.assertEqual(state["pendingCount"], 216)
        with self.assertRaisesRegex(ProofPlaneError, "initialization differs"):
            StudyRunController(
                private_root=self.fixture.root,
                expected_run_set_path=self.fixture.expected_path,
                schedule=self.fixture.schedule,
                max_parallel=1,
            ).status()

    def test_private_permissions_and_symlink_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            public_root = Path(temporary).resolve()
            os.chmod(public_root, 0o755)
            with self.assertRaisesRegex(ProofPlaneError, "mode-0700"):
                StudyRunController(
                    private_root=public_root,
                    expected_run_set_path=self.fixture.expected_path,
                    schedule=self.fixture.schedule,
                    max_parallel=2,
                )
        expected_link = self.fixture.root / "expected-link.json"
        expected_link.symlink_to(self.fixture.expected_path)
        with self.assertRaisesRegex(ProofPlaneError, "regular file"):
            StudyRunController(
                private_root=self.fixture.root,
                expected_run_set_path=expected_link,
                schedule=self.fixture.schedule,
                max_parallel=2,
            )

    def test_exact_reservation_order_and_max_parallel(self) -> None:
        self.fixture.controller.initialize()
        first = self.fixture.controller.reserve_next()
        second = self.fixture.controller.reserve_next()
        self.assertEqual(first["runId"], self.fixture.schedule[0]["runId"])
        self.assertEqual(second["runId"], self.fixture.schedule[1]["runId"])
        self.assertIsNone(self.fixture.controller.reserve_next())

    def test_reservation_handle_binds_exact_anchored_entry_and_closed_plan(self) -> None:
        self.fixture.controller.initialize()
        reservation = self.fixture.controller.reserve_next()
        self.assertIsInstance(reservation, ReservationHandle)
        reservation_checkpoint = next(
            path
            for path in self.fixture.controller.checkpoints.iterdir()
            if load_json(path)["revision"] == 2
        )
        checkpoint = load_json(reservation_checkpoint)
        self.assertEqual(
            reservation["reservationEntrySha256"], checkpoint["terminalHeadSha256"]
        )
        expected = next(
            item
            for item in self.fixture.expected_runs
            if item["runId"] == reservation["runId"]
        )
        plan = _fixture_attempt_plan(reservation["runId"], expected["baselineCommit"])
        self.assertEqual(len(plan), 10)
        substitute_plan = plan.as_dict()
        substitute_plan["runtimeTcbSha256"] = _digest("substitute-runtime-tcb")
        with self.assertRaisesRegex(ProofPlaneError, "runtime TCB differs"):
            self.fixture.controller.begin_reserved_attempt(
                reservation,
                substitute_plan,
                started_at="2026-08-13T00:10:00Z",
            )
        start_path = self.fixture.controller.begin_reserved_attempt(
            reservation, plan, started_at="2026-08-13T00:10:00Z"
        )
        start = load_json(start_path)
        self.assertEqual(start["reservationEntrySha256"], reservation["reservationEntrySha256"])
        self.assertEqual(start["trustedAttemptPlan"], plan.as_dict())
        self.assertEqual(start["trustedAttemptPlanSha256"], plan.sha256)
        state = self.fixture.controller.status()
        self.assertEqual(state["active"][0]["lifecycle"], "started")
        self.assertEqual(state["active"][0]["startReceiptSha256"], file_digest(start_path))
        with self.assertRaisesRegex(ProofPlaneError, "already started"):
            self.fixture.controller.begin_reserved_attempt(reservation, plan)

    def test_released_and_fabricated_reservation_handles_cannot_start(self) -> None:
        self.fixture.controller.initialize()
        stale = self.fixture.controller.reserve_next()
        expected = next(
            item for item in self.fixture.expected_runs if item["runId"] == stale["runId"]
        )
        plan = _fixture_attempt_plan(stale["runId"], expected["baselineCommit"])
        self.fixture.controller.release_prestart(stale["runId"], reason="preparation failed")
        current = self.fixture.controller.reserve_next()
        self.assertEqual(current["runId"], stale["runId"])
        self.assertNotEqual(
            current["reservationEntrySha256"], stale["reservationEntrySha256"]
        )
        with self.assertRaisesRegex(ProofPlaneError, "differs from the active"):
            self.fixture.controller.begin_reserved_attempt(stale, plan)
        fabricated = dict(current)
        fabricated["reservationEntrySha256"] = _digest("fabricated")
        with self.assertRaisesRegex(ProofPlaneError, "differs from the active"):
            self.fixture.controller.begin_reserved_attempt(fabricated, plan)

    def test_complete_start_publication_is_reconciled_after_controller_crash(self) -> None:
        self.fixture.controller.initialize()
        reservation = self.fixture.controller.reserve_next()
        expected = next(
            item
            for item in self.fixture.expected_runs
            if item["runId"] == reservation["runId"]
        )
        plan = _fixture_attempt_plan(reservation["runId"], expected["baselineCommit"])
        with patch.object(
            self.fixture.controller,
            "_append",
            side_effect=RuntimeError("simulated crash after complete start publication"),
        ):
            with self.assertRaisesRegex(RuntimeError, "complete start publication"):
                self.fixture.controller.begin_reserved_attempt(
                    reservation, plan, started_at="2026-08-13T00:10:00Z"
                )
        state = self.fixture.controller.status()
        self.assertEqual(state["journalRecordCount"], 3)
        self.assertEqual(state["active"][0]["lifecycle"], "started")
        self.assertEqual(
            state["active"][0]["reservationEntrySha256"],
            reservation["reservationEntrySha256"],
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires process file locking")
    def test_concurrent_start_consumes_one_reservation_exactly_once(self) -> None:
        self.fixture.controller.initialize()
        reservation = self.fixture.controller.reserve_next()
        expected = next(
            item
            for item in self.fixture.expected_runs
            if item["runId"] == reservation["runId"]
        )
        plan = _fixture_attempt_plan(reservation["runId"], expected["baselineCommit"])
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        processes = [
            context.Process(
                target=_begin_in_process,
                args=(
                    str(self.fixture.root),
                    str(self.fixture.expected_path),
                    self.fixture.schedule,
                    reservation.as_dict(),
                    plan.as_dict(),
                    queue,
                ),
            )
            for _index in range(2)
        ]
        for process in processes:
            process.start()
        results = [queue.get(timeout=20) for _process in processes]
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(len([item for item in results if item[0] == "ok"]), 1)
        self.assertEqual(len([item for item in results if item[0] == "error"]), 1)
        self.assertIn("already started", [item[1] for item in results if item[0] == "error"][0])

    @unittest.skipUnless(hasattr(os, "fork"), "requires process file locking")
    def test_concurrent_reservations_are_distinct_and_ordered(self) -> None:
        self.fixture.controller.initialize()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        processes = [
            context.Process(
                target=_reserve_in_process,
                args=(
                    str(self.fixture.root),
                    str(self.fixture.expected_path),
                    self.fixture.schedule,
                    queue,
                ),
            )
            for _index in range(4)
        ]
        for process in processes:
            process.start()
        results = [queue.get(timeout=10) for _process in processes]
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        successes = sorted(value for status, value in results if status == "ok" and value)
        self.assertEqual(
            successes,
            sorted([self.fixture.schedule[0]["runId"], self.fixture.schedule[1]["runId"]]),
        )
        self.assertFalse([value for status, value in results if status == "error"])
        self.assertEqual(len(self.fixture.controller.status()["active"]), 2)

    def test_prestart_release_quarantines_and_retries_same_cell(self) -> None:
        self.fixture.controller.initialize()
        reservation = self.fixture.controller.reserve_next()
        paths = self.fixture.paths(reservation["runId"])
        paths["artifacts"].mkdir(parents=True, mode=0o700)
        os.chmod(paths["artifacts"].parent, 0o700)
        (paths["artifacts"] / "partial.txt").write_text("partial", encoding="utf-8")
        os.chmod(paths["artifacts"] / "partial.txt", 0o600)
        state = self.fixture.controller.release_prestart(
            reservation["runId"], reason="host preparation failed"
        )
        self.assertEqual(state["nextPendingOrdinal"], 1)
        self.assertFalse(paths["artifacts"].exists())
        quarantine = next(
            path
            for path in self.fixture.controller.quarantine.iterdir()
            if path.is_dir()
        )
        retained = quarantine / paths["artifacts"].name / "partial.txt"
        retained.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ProofPlaneError, "content changed"):
            self.fixture.controller.status()
        retained.write_text("partial", encoding="utf-8")
        self.assertEqual(
            self.fixture.controller.reserve_next()["runId"], reservation["runId"]
        )
        with self.assertRaisesRegex(ProofPlaneError, "scored start"):
            self.fixture.write_attempt(reservation["runId"], 1)
            self.fixture.controller.release_prestart(
                reservation["runId"], reason="must not retry a scored invocation"
            )

    def test_terminal_reconciliation_binds_exact_evidence_and_is_idempotent(self) -> None:
        self.fixture.controller.initialize()
        reservation = self.fixture.controller.reserve_next()
        terminal = self.fixture.write_attempt(reservation["runId"], reservation["ordinal"])
        before = self.fixture.controller.status()
        self.assertEqual(before["recoveryRequiredCount"], 0)
        self.assertEqual(before["active"][0]["lifecycle"], "started")
        with self.assertRaisesRegex(ProofPlaneError, "scored start"):
            self.fixture.controller.release_prestart(
                reservation["runId"], reason="a scored run must never be retried"
            )
        state = self.fixture.controller.reconcile_terminal_receipts()
        self.assertEqual(state["terminalCount"], 1)
        self.assertEqual(state["recoveryRequiredCount"], 0)
        self.assertEqual(self.fixture.controller.reconcile_terminal_receipts(), state)
        tampered = load_json(terminal)
        tampered["terminal"]["patchSha256"] = _digest("forged-patch")
        _write_canonical(terminal, tampered)
        with self.assertRaisesRegex(ProofPlaneError, "differs from controller history"):
            self.fixture.controller.status()

    def test_crash_after_journal_append_catches_up_anchor_and_state(self) -> None:
        self.fixture.controller.initialize()
        real_advance = __import__(
            "tools.proof_plane.controller", fromlist=["advance_ledger_anchor"]
        ).advance_ledger_anchor
        with patch(
            "tools.proof_plane.controller.advance_ledger_anchor",
            side_effect=RuntimeError("simulated crash after append"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                self.fixture.controller.reserve_next()
        state = self.fixture.controller.status()
        self.assertEqual(state["journalRecordCount"], 2)
        self.assertEqual(state["active"][0]["ordinal"], 1)
        self.assertEqual(
            state["journalAnchorSha256"],
            load_json(self.fixture.controller.anchor_path)["anchorSha256"],
        )
        self.assertIsNotNone(real_advance)

    def test_crash_after_anchor_advance_repairs_only_missing_suffix_checkpoint(self) -> None:
        self.fixture.controller.initialize()
        with patch.object(
            self.fixture.controller,
            "_write_checkpoint",
            side_effect=RuntimeError("simulated crash after anchor"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                self.fixture.controller.reserve_next()
        state = self.fixture.controller.status()
        self.assertEqual(state["journalRecordCount"], 2)
        self.assertEqual(len(list(self.fixture.controller.checkpoints.iterdir())), 3)

    def test_journal_anchor_and_checkpoint_tampering_fail_closed(self) -> None:
        self.fixture.controller.initialize()
        self.fixture.controller.reserve_next()
        journal = self.fixture.controller.journal_path
        original = journal.read_bytes()
        journal.write_bytes(original.replace(b'"kind":"reserved"', b'"kind":"forgerxx"'))
        with self.assertRaises(ProofPlaneError):
            self.fixture.controller.status()

        # Restore a clean independent fixture to test retained-anchor rollback.
        self.fixture.close()
        self.fixture = ControllerFixture()
        self.fixture.controller.initialize()
        genesis = next(self.fixture.controller.checkpoints.iterdir())
        genesis_checkpoint = load_json(genesis)
        self.fixture.controller.reserve_next()
        anchor = load_json(self.fixture.controller.anchor_path)
        anchor.update(
            {
                "revision": genesis_checkpoint["revision"],
                "recordCount": genesis_checkpoint["recordCount"],
                "terminalHeadSha256": genesis_checkpoint["terminalHeadSha256"],
                "previousAnchorSha256": "0" * 64,
                "recordedAt": "2026-08-13T00:00:00Z",
            }
        )
        body = {key: anchor[key] for key in (
            "schemaVersion", "revision", "recordCount", "terminalHeadSha256",
            "previousAnchorSha256", "recordedAt",
        )}
        anchor["anchorSha256"] = canonical_digest(body)
        _write_canonical(self.fixture.controller.anchor_path, anchor)
        with self.assertRaises(ProofPlaneError):
            self.fixture.controller.status()

        # A damaged retained checkpoint is also fatal.
        self.fixture.close()
        self.fixture = ControllerFixture()
        self.fixture.controller.initialize()
        checkpoint = next(
            path
            for path in self.fixture.controller.checkpoints.iterdir()
            if load_json(path)["revision"] == 0
        )
        value = load_json(checkpoint)
        value["recordCount"] = 1
        _write_canonical(checkpoint, value)
        with self.assertRaises(ProofPlaneError):
            self.fixture.controller.status()

    def test_full_216_terminal_set_and_seal_recovery(self) -> None:
        self.fixture.controller.initialize()
        for item in self.fixture.schedule:
            reservation = self.fixture.controller.reserve_next()
            self.assertEqual(reservation["runId"], item["runId"])
            terminal = self.fixture.write_attempt(item["runId"], item["ordinal"])
            self.fixture.controller.record_terminal(item["runId"], terminal)
        output = self.fixture.root / "terminal-set.json"
        real_write = __import__(
            "tools.proof_plane.controller", fromlist=["write_canonical_json_once"]
        ).write_canonical_json_once

        def write_then_crash(path, document):
            real_write(path, document)
            raise RuntimeError("simulated crash after terminal-set write")

        with patch(
            "tools.proof_plane.controller.write_canonical_json_once",
            side_effect=write_then_crash,
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                self.fixture.controller.seal(output)
        pending = self.fixture.controller.status()
        self.assertIsNotNone(pending["sealPending"])
        self.assertFalse(pending["sealed"])
        with self.assertRaisesRegex(ProofPlaneError, "pending recovery"):
            self.fixture.controller.reserve_next()
        sealed = self.fixture.controller.seal(output)
        self.assertTrue(sealed["sealed"])
        self.assertEqual(sealed["terminalCount"], 216)
        self.assertEqual(load_json(output)["runCount"], 216)
        self.assertEqual(self.fixture.controller.seal(output), sealed)


if __name__ == "__main__":
    unittest.main()
