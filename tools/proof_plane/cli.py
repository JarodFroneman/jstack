#!/usr/bin/env python3
"""Maintainer-only CLI for the uninstalled Beta.1 Proof Plane."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from evals.runner.contracts import ContractError, validate_manifest

from .common import ProofPlaneError, atomic_write_json, load_json, resolve_within
from .lifecycle import (
    admit_study,
    finalize_study,
    fixed_layout,
    grade_study,
    prepare_study,
    qualify_images,
    review_study,
    runtime_bootstrap_control,
    run_study_control,
    study_doctor,
    task_artifact_task_ids,
    task_artifacts_control,
    verify_study,
)
from .preregistration import preregistration_candidate_control
from .study import execution_schedule, freeze_manifest, gap_report, validate_bundle, validate_registration


ROOT = Path(__file__).resolve().parents[2]


def _print(value: Any) -> None:
    sys.stdout.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _absolute_unresolved(path: Path) -> Path:
    """Make a CLI path absolute without hiding a final-component symlink."""

    return path if path.is_absolute() else (Path.cwd() / path).absolute()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Operate JStack's uninstalled Beta.1 Proof Plane.")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-bundle")
    validate.add_argument("registration", type=Path)

    freeze = sub.add_parser("freeze-manifest")
    freeze.add_argument("registration", type=Path)
    freeze.add_argument("--output", required=True, type=Path)

    schedule = sub.add_parser("schedule")
    schedule.add_argument("registration", type=Path)
    schedule.add_argument("--output", type=Path)

    report = sub.add_parser("gap-report")
    report.add_argument("registration", type=Path)
    report.add_argument("--expected-run-set", required=True, type=Path)
    report.add_argument("--terminal-set", required=True, type=Path)
    report.add_argument("--runs", required=True, type=Path)
    report.add_argument("--reviews", required=True, type=Path)
    report.add_argument("--attestations", required=True, type=Path)
    report.add_argument("--verification-receipt", required=True, type=Path)
    report.add_argument("--verification-signature", required=True, type=Path)
    report.add_argument("--output", type=Path)

    prepare = sub.add_parser(
        "prepare-study",
        help="create the fixed private layout and import reviewed inputs",
    )
    prepare.add_argument("--qualification-plan", type=Path)
    prepare.add_argument("--reviewer-roster", type=Path)
    prepare.add_argument("--evidence-verifier-roster", type=Path)
    prepare.add_argument("--image-builder-roster", type=Path)
    prepare.add_argument("--review-packet-secret", type=Path)
    prepare.add_argument(
        "--image-build-inputs-root",
        type=Path,
        help="import the reviewed matrix plus exact 18 build contexts once",
    )
    prepare.add_argument(
        "--tas" "k-artifact-curator-roster",
        type=Path,
        help="import the one-key curator roster with the exact reviewed holdout set",
    )
    prepare.add_argument(
        "--reviewed-tas" "k-artifact-inputs-root",
        type=Path,
        help="import exactly 18 fixed holdout.bundle plus SSHSIG pairs once",
    )

    sub.add_parser(
        "study-doctor",
        help="report concrete local study blockers without mutation",
    )

    runtime_bootstrap = sub.add_parser(
        "runtime-bootstrap",
        help="inspect, start, or recover the fixed dedicated Apple runtime",
    )
    runtime_bootstrap.add_argument(
        "action", choices=("status", "start", "recover")
    )

    preregistration = sub.add_parser(
        "prepare-registration-candidate",
        help="build, inspect, or publish the fixed non-authorizing Beta.1 candidate",
    )
    preregistration.add_argument(
        "action", choices=("status", "build", "publish")
    )

    task_artifacts = sub.add_parser(
        "task-artifacts",
        help="operate the closed reviewed holdout and baseline lifecycle",
    )
    task_artifacts.add_argument(
        "action",
        choices=("stage", "import", "baseline", "recover", "publish", "status"),
    )
    task_artifacts.add_argument(
        "task_id",
        nargs="?",
        choices=task_artifact_task_ids(),
    )

    qualify = sub.add_parser(
        "qualify-images",
        help="build, qualify, or inspect the closed 18-image lifecycle",
    )
    qualify.add_argument(
        "action", choices=("build", "recover", "attest", "qualify", "status")
    )

    admit = sub.add_parser(
        "admit-study",
        help="run live preflight and freeze the exact 216-run admission set",
    )
    admit.add_argument("registration", type=Path)

    run = sub.add_parser(
        "run-study",
        help="inspect or execute one controller-bound study cell per invocation",
    )
    run.add_argument("registration", type=Path)
    run.add_argument(
        "action",
        choices=("initialize", "status", "execute", "resume", "seal"),
    )

    grade = sub.add_parser(
        "grade-study",
        help="grade all 216 terminal attempts behind the global holdout gate",
    )
    grade.add_argument("registration", type=Path)

    review = sub.add_parser(
        "review-study",
        help="prepare, inspect, or finalize the signed human-review lifecycle",
    )
    review.add_argument("registration", type=Path)
    review.add_argument("action", choices=("prepare", "status", "finalize"))

    verify = sub.add_parser(
        "verify-study",
        help="assemble or verify the closed private evidence set",
    )
    verify.add_argument("registration", type=Path)
    verify.add_argument("action", choices=("assemble", "verify"))

    finalize = sub.add_parser(
        "finalize-study",
        help="publish score and gap only after the verifier signature exists",
    )
    finalize.add_argument("registration", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "validate-bundle":
            value = validate_bundle(args.registration, repo_root=ROOT)
        elif args.command == "freeze-manifest":
            registration = validate_registration(load_json(args.registration), repo_root=ROOT)
            manifest_path = resolve_within(ROOT, registration["manifestPath"], "manifest")
            manifest = validate_manifest(load_json(manifest_path))
            value = freeze_manifest(manifest, registration, repo_root=ROOT)
            output = args.output.resolve()
            if output == manifest_path.resolve():
                raise ProofPlaneError("freeze-manifest must write a reviewed staging path, not replace the source in place")
            atomic_write_json(output, value)
            value = {"written": str(output), "runCount": len(value["executionPlan"]["expectedRuns"])}
        elif args.command == "schedule":
            registration = validate_registration(load_json(args.registration), repo_root=ROOT)
            manifest = validate_manifest(load_json(resolve_within(ROOT, registration["manifestPath"], "manifest")))
            value = execution_schedule(manifest["executionPlan"]["expectedRuns"], registration["schedule"]["seedSha256"])
            if args.output:
                atomic_write_json(args.output.resolve(), value)
                value = {"written": str(args.output.resolve()), "runCount": len(value)}
        elif args.command == "gap-report":
            layout = fixed_layout(ROOT)
            value = gap_report(
                args.registration,
                repo_root=ROOT,
                expected_run_set_path=args.expected_run_set,
                terminal_set_path=args.terminal_set,
                task_artifact_set_summary_path=layout.task_artifact_set_summary,
                evidence_index_path=layout.evidence / "evidence-index.json",
                runs_directory=args.runs,
                reviews_directory=args.reviews,
                attestations_directory=args.attestations,
                verification_receipt_path=args.verification_receipt,
                verification_signature_path=args.verification_signature,
            )
            if args.output:
                atomic_write_json(args.output.resolve(), value)
                value = {"written": str(args.output.resolve()), "eligibleForScoring": value["eligibleForScoring"]}
        elif args.command == "prepare-study":
            value = prepare_study(
                repo_root=ROOT,
                qualification_plan_path=(
                    _absolute_unresolved(args.qualification_plan)
                    if args.qualification_plan is not None
                    else None
                ),
                reviewer_roster_path=(
                    _absolute_unresolved(args.reviewer_roster)
                    if args.reviewer_roster is not None
                    else None
                ),
                evidence_verifier_roster_path=(
                    _absolute_unresolved(args.evidence_verifier_roster)
                    if args.evidence_verifier_roster is not None
                    else None
                ),
                image_builder_roster_path=(
                    _absolute_unresolved(args.image_builder_roster)
                    if args.image_builder_roster is not None
                    else None
                ),
                packet_secret_path=(
                    _absolute_unresolved(args.review_packet_secret)
                    if args.review_packet_secret is not None
                    else None
                ),
                image_build_inputs_root=(
                    _absolute_unresolved(args.image_build_inputs_root)
                    if args.image_build_inputs_root is not None
                    else None
                ),
                task_artifact_curator_roster_path=(
                    _absolute_unresolved(args.task_artifact_curator_roster)
                    if args.task_artifact_curator_roster is not None
                    else None
                ),
                reviewed_task_artifact_inputs_root=(
                    _absolute_unresolved(args.reviewed_task_artifact_inputs_root)
                    if args.reviewed_task_artifact_inputs_root is not None
                    else None
                ),
            )
        elif args.command == "study-doctor":
            value = study_doctor(repo_root=ROOT)
        elif args.command == "runtime-bootstrap":
            value = runtime_bootstrap_control(repo_root=ROOT, action=args.action)
        elif args.command == "prepare-registration-candidate":
            value = preregistration_candidate_control(
                repo_root=ROOT, action=args.action
            )
        elif args.command == "task-artifacts":
            value = task_artifacts_control(
                repo_root=ROOT,
                action=args.action,
                task_id=args.task_id,
            )
        elif args.command == "qualify-images":
            value = qualify_images(repo_root=ROOT, action=args.action)
        elif args.command == "admit-study":
            value = admit_study(
                registration_path=_absolute_unresolved(args.registration), repo_root=ROOT
            )
        elif args.command == "run-study":
            value = run_study_control(
                registration_path=_absolute_unresolved(args.registration),
                repo_root=ROOT,
                action=args.action,
            )
        elif args.command == "grade-study":
            value = grade_study(
                registration_path=_absolute_unresolved(args.registration), repo_root=ROOT
            )
        elif args.command == "review-study":
            value = review_study(
                registration_path=_absolute_unresolved(args.registration),
                repo_root=ROOT,
                action=args.action,
            )
        elif args.command == "verify-study":
            value = verify_study(
                registration_path=_absolute_unresolved(args.registration),
                repo_root=ROOT,
                action=args.action,
            )
        elif args.command == "finalize-study":
            value = finalize_study(
                registration_path=_absolute_unresolved(args.registration), repo_root=ROOT
            )
        else:  # pragma: no cover - argparse closes this branch.
            raise ProofPlaneError("unsupported Proof Plane command")
        _print(value)
    except (ProofPlaneError, ContractError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
