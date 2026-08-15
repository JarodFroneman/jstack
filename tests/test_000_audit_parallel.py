"""Run the unchanged unittest modules in parallel for the bounded audit adapter.

The ordinary QA command keeps Python's normal serial discovery semantics.  The
curated JStack audit adapter sets ``JSTACK_AUDIT_EXECUTION=1`` and has a fixed
five-minute ceiling, so this first-discovered module replaces the outer suite
with one coordinator test.  The coordinator launches every other discovered
test module in an isolated subprocess, removes the audit marker to prevent
recursion, and fails unless every module succeeds.  No test module is skipped;
only their scheduling changes.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List


_AUDIT_EXECUTION = os.environ.get("JSTACK_AUDIT_EXECUTION") == "1"


def _empty_module_suite(
    loader: unittest.TestLoader,
    module: Any,
    *args: Any,
    **kwargs: Any,
) -> unittest.TestSuite:
    del loader, module, args, kwargs
    return unittest.TestSuite()


def _skip_discovery_path(
    loader: unittest.TestLoader,
    full_path: str,
    pattern: str,
) -> Any:
    del loader, full_path, pattern
    return None, False


def load_tests(
    loader: unittest.TestLoader,
    standard_tests: unittest.TestSuite,
    pattern: str,
) -> unittest.TestSuite:
    del pattern
    if _AUDIT_EXECUTION:
        # Discovery sorts filenames, so this module is imported before every
        # other test_*.py module.  Patch this discovery loader instance after
        # its coordinator tests are loaded; the other modules are still run
        # below in clean interpreters with ordinary unittest semantics.
        loader.loadTestsFromModule = types.MethodType(
            _empty_module_suite, loader
        )
        loader._find_test_path = types.MethodType(  # type: ignore[attr-defined]
            _skip_discovery_path, loader
        )
    return standard_tests


def _run_module(repo_root: Path, scratch: Path, path: Path) -> Dict[str, Any]:
    worker_root = scratch / path.stem
    worker_root.mkdir(mode=0o700)
    environment = dict(os.environ)
    environment.pop("JSTACK_AUDIT_EXECUTION", None)
    environment["HOME"] = str(worker_root)
    environment["TMPDIR"] = str(worker_root)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            path.name,
            "-q",
        ],
        cwd=str(repo_root),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=240,
        check=False,
    )
    output = process.stdout + process.stderr
    match = re.search(rb"Ran ([0-9]+) tests? in ", output)
    return {
        "module": path.name,
        "returnCode": process.returncode,
        "testCount": int(match.group(1)) if match else None,
        "outputSha256": hashlib.sha256(output).hexdigest(),
        "failureTail": output[-4000:].decode("utf-8", errors="replace")
        if process.returncode
        else None,
    }


if _AUDIT_EXECUTION:

    class AuditParallelUnittestTests(unittest.TestCase):
        def test_all_discovered_modules_pass_in_isolated_workers(self) -> None:
            repo_root = Path(__file__).resolve().parents[1]
            module_paths = sorted(
                path
                for path in (repo_root / "tests").glob("test_*.py")
                if path.name != Path(__file__).name
            )
            self.assertTrue(module_paths)
            with tempfile.TemporaryDirectory(
                prefix="jstack-audit-unittest-"
            ) as temporary:
                scratch = Path(temporary)
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    results: List[Dict[str, Any]] = list(
                        pool.map(
                            lambda path: _run_module(
                                repo_root, scratch, path
                            ),
                            module_paths,
                        )
                    )
            failures = [item for item in results if item["returnCode"] != 0]
            missing_counts = [
                item["module"] for item in results if item["testCount"] is None
            ]
            self.assertFalse(
                failures,
                "parallel audit unittest failures: "
                + json.dumps(failures, sort_keys=True),
            )
            self.assertFalse(
                missing_counts,
                "parallel audit unittest output lacked counts: "
                + json.dumps(missing_counts),
            )
            print(
                json.dumps(
                    {
                        "auditParallelModuleCount": len(results),
                        "auditParallelTestCount": sum(
                            int(item["testCount"]) for item in results
                        ),
                        "moduleEvidence": [
                            {
                                "module": item["module"],
                                "outputSha256": item["outputSha256"],
                                "testCount": item["testCount"],
                            }
                            for item in results
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
