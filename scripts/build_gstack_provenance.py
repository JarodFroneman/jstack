#!/usr/bin/env python3
"""Build or verify JStack's immutable gstack provenance manifest."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mcp.jstack.upstream.gstack.provenance import (  # noqa: E402
    GstackProvenanceError,
    MANIFEST_PATH,
    PLAN_PATH,
    build_manifest,
    canonical_manifest_bytes,
    load_plan,
    verify_local_targets,
    verify_source_tree,
)


def _write_atomic(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, default=PLAN_PATH)
    parser.add_argument("--output", type=Path, default=MANIFEST_PATH)
    arguments = parser.parse_args()

    try:
        plan = load_plan(arguments.plan)
        manifest = build_manifest(
            plan,
            source_root=arguments.source_root,
            local_root=ROOT,
        )
        expected = canonical_manifest_bytes(manifest)
        if arguments.write:
            _write_atomic(arguments.output, expected)
        else:
            try:
                actual = arguments.output.read_bytes()
            except OSError as exc:
                raise GstackProvenanceError(
                    f"Unable to read generated provenance manifest: {exc}"
                ) from exc
            if actual != expected:
                raise GstackProvenanceError(
                    "Generated gstack provenance manifest is stale; run with --write."
                )
        verify_source_tree(manifest, source_root=arguments.source_root)
        verify_local_targets(manifest, local_root=ROOT)
    except GstackProvenanceError as exc:
        print(f"gstack provenance error: {exc}", file=sys.stderr)
        return 1

    verb = "wrote" if arguments.write else "verified"
    print(
        f"JStack {verb} immutable gstack provenance for "
        f"{manifest['source']['commit']} ({len(manifest['sourceInventory'])} files, "
        f"{len(manifest['records'])} records)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
