#!/usr/bin/env python3
"""Validate a JStack CSO report without external dependencies."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from cso_core import validate_security_report
from secure_io import read_bounded_regular_file


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a JStack CSO JSON report.")
    parser.add_argument("report", help="Path to the report JSON")
    args = parser.parse_args(argv)
    try:
        report = json.loads(read_bounded_regular_file(Path(args.report)).decode("utf-8"))
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        sys.stderr.write("jstack-cso-validate-report: %s\n" % exc)
        return 2
    errors = validate_security_report(report)
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
