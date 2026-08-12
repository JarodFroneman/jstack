#!/usr/bin/env python3
"""Command-line entry point for local Proof Plane contract checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List, Optional

from .contracts import ContractError, load_document, validate_document, validate_lock
from .mock import run_mock_scenario
from .score import bind_execution_plan, score_runs


EVAL_ROOT = Path(__file__).resolve().parents[1]


def _write_json(value: Any) -> None:
    sys.stdout.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _reject_duplicate_keys(pairs: List[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("%s contains a duplicate object key" % key)
        value[key] = item
    return value


def _load_array(path: Path, field: str) -> List[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ContractError("%s path must be a regular, non-symlink file" % field)
    if path.stat().st_size > 20_000_000:
        raise ContractError("%s exceeds the 20 MB input limit" % field)
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ContractError("%s must be a JSON array of objects" % field)
    return value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and score JStack Proof Plane artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate one public contract document.")
    validate_parser.add_argument("path", type=Path)

    lock_parser = subparsers.add_parser("verify-lock", help="Verify the development corpus lock.")
    lock_parser.add_argument("path", type=Path, default=EVAL_ROOT / "corpus" / "corpus-lock.json", nargs="?")

    mock_parser = subparsers.add_parser("mock-run", help="Run an inert deterministic mock scenario and print its score.")
    mock_parser.add_argument("scenario", type=Path)

    score_parser = subparsers.add_parser("score", help="Score pre-existing run and review envelope arrays.")
    score_parser.add_argument("--runs", type=Path, required=True)
    score_parser.add_argument("--reviews", type=Path, required=True)
    score_parser.add_argument("--manifest", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            document = validate_document(load_document(args.path))
            _write_json({"valid": True, "schemaVersion": document["schemaVersion"]})
        elif args.command == "verify-lock":
            lock = load_document(args.path)
            validate_lock(lock, eval_root=EVAL_ROOT)
            _write_json({"valid": True, "schemaVersion": lock["schemaVersion"], "fileCount": len(lock["files"])})
        elif args.command == "mock-run":
            scenario = load_document(args.scenario)
            runs, reviews = run_mock_scenario(scenario)
            manifest = bind_execution_plan(
                load_document(EVAL_ROOT / "corpus" / "public" / "manifest.v1.json"),
                runs,
                plan_id="alpha.10-deterministic-mock",
            )
            manifest["corpusId"] = scenario["corpus"]["id"]
            manifest["corpusVersion"] = scenario["corpus"]["version"]
            _write_json(
                score_runs(
                    runs,
                    reviews,
                    manifest=manifest,
                )
            )
        else:
            _write_json(
                score_runs(
                    _load_array(args.runs, "runs"),
                    _load_array(args.reviews, "reviews"),
                    manifest=load_document(args.manifest),
                )
            )
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
