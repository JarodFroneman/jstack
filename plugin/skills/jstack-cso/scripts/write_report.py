#!/usr/bin/env python3
"""Validate JSON from stdin, then create one confined JStack CSO report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from cso_core import validate_security_report
from secure_io import read_bounded_stream, write_private_new_file


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate stdin and create an owner-private JStack CSO report."
    )
    parser.add_argument("--root", default=".", help="Authorized repository root")
    parser.add_argument(
        "--output",
        required=True,
        help="Direct child under <root>/.jstack/security-reports/",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print stored JSON")
    args = parser.parse_args(argv)
    try:
        raw = read_bounded_stream(sys.stdin.buffer)
        report = json.loads(raw.decode("utf-8"))
        errors = validate_security_report(report)
        if errors:
            sys.stderr.write("\n".join(errors) + "\n")
            return 1
        serialized = json.dumps(report, indent=2 if args.pretty else None, sort_keys=True) + "\n"
        output = write_private_new_file(Path(args.root), args.output, serialized)
        print(output.relative_to(Path(args.root).expanduser().resolve(strict=True)).as_posix())
        return 0
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        sys.stderr.write("jstack-cso-write-report: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
