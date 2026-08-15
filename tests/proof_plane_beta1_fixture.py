"""Test-only export of the immutable Beta.1 Proof Plane checkout."""

from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
BETA1_TAG = "v0.10.0-beta.1"
BETA1_COMMIT = "7c38496febbd6aa60b51e119287e92d63a9f32ca"


def export_frozen_beta1_checkout(destination: Path) -> Path:
    """Export the exact annotated Beta.1 tree without mutating Git state."""

    object_type = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-t", BETA1_TAG],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if object_type != "tag":
        raise AssertionError(f"{BETA1_TAG} must be an annotated tag")
    commit = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", f"{BETA1_TAG}^{{}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if commit != BETA1_COMMIT:
        raise AssertionError(
            f"{BETA1_TAG} resolved to {commit!r}, expected {BETA1_COMMIT!r}"
        )

    archive = destination / "beta1.tar"
    subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "archive",
            "--format=tar",
            f"--output={archive}",
            f"{BETA1_TAG}^{{}}",
        ],
        check=True,
        capture_output=True,
    )
    checkout = destination / "checkout"
    checkout.mkdir()
    with tarfile.open(archive, mode="r:") as bundle:
        for member in bundle.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise AssertionError(
                    f"unsafe path in {BETA1_TAG} archive: {member.name!r}"
                )
            target = checkout.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise AssertionError(
                    f"unsupported member type in {BETA1_TAG} archive: {member.name!r}"
                )
            source = bundle.extractfile(member)
            if source is None:
                raise AssertionError(
                    f"unable to read {member.name!r} from {BETA1_TAG}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())
    return checkout
