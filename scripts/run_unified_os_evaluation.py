#!/usr/bin/env python3
"""Validate or instantiate the development-only Unified OS evaluation plan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from unified_os_evals import (  # noqa: E402
    EvaluationProtocolError,
    build_execution_plan,
    load_template,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-template")
    validate.add_argument("--template")
    instantiate = subparsers.add_parser("instantiate")
    instantiate.add_argument("--template")
    instantiate.add_argument("--candidate-commit", required=True)
    instantiate.add_argument("--candidate-tree", required=True)
    instantiate.add_argument("--environment-digest", required=True)
    args = parser.parse_args(argv)
    try:
        template = load_template(args.template)
        if args.command == "validate-template":
            result = {
                "valid": True,
                "studyId": template["studyId"],
                "currentResultState": template["currentResultState"],
                "claimStatus": template["claimStatus"],
            }
        else:
            result = build_execution_plan(
                template,
                combined_candidate_commit=args.candidate_commit,
                combined_candidate_tree=args.candidate_tree,
                environment_digest=args.environment_digest,
            )
    except EvaluationProtocolError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
