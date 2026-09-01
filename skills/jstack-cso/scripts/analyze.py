#!/usr/bin/env python3
"""CLI for the JStack CSO deterministic evidence collector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from cso_core import analyze_repository, validate_evidence_bundle
from secure_io import write_private_new_file


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only JStack CSO enterprise security evidence collector."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--output", help="Direct child under <root>/.jstack/security-reports/")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--max-files", type=_positive_integer)
    parser.add_argument("--max-file-bytes", type=_positive_integer)
    parser.add_argument("--max-total-bytes", type=_positive_integer)
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve(strict=True)
        limits = {
            key: value
            for key, value in {
                "maxFiles": args.max_files,
                "maxFileBytes": args.max_file_bytes,
                "maxTotalBytes": args.max_total_bytes,
            }.items()
            if value is not None
        }
        bundle = analyze_repository(root, limits=limits)
        errors = validate_evidence_bundle(bundle)
        if errors:
            raise RuntimeError("internal evidence validation failed:\n" + "\n".join(errors))
        serialized = json.dumps(bundle, indent=2 if args.pretty else None, sort_keys=True) + "\n"
        if args.output:
            output = write_private_new_file(root, args.output, serialized)
            print(output.relative_to(root).as_posix())
        else:
            sys.stdout.write(serialized)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        sys.stderr.write("jstack-cso-analyze: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
