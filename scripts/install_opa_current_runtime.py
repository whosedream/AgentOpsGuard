#!/usr/bin/env python3
"""Install the reviewed OPA runtime outside the repository after digest checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


OPA_VERSION = "1.20.1"
OPA_ASSET_NAME = "opa_linux_amd64_static"
OPA_BINARY_SHA256 = "0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f"
DEFAULT_DESTINATION = Path.home() / f".local/share/agentops-guard/opa/{OPA_VERSION}/opa"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_checksum_file(path: Path) -> None:
    fields = path.read_text(encoding="utf-8-sig").strip().split()
    if len(fields) != 2:
        raise RuntimeError("OPA checksum file has an unexpected format")
    checksum, asset_name = fields
    if checksum.lower() != OPA_BINARY_SHA256 or asset_name.lstrip("*") != OPA_ASSET_NAME:
        raise RuntimeError("OPA checksum file does not match the reviewed release asset")


def _verify_version(path: Path) -> None:
    result = subprocess.run(
        (str(path), "version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("installed OPA binary did not run")
    version_text = result.stdout.decode("utf-8", errors="replace")
    if f"Version: {OPA_VERSION}\n" not in version_text:
        raise RuntimeError("installed OPA binary reported an unexpected version")


def install(source: Path, checksum_file: Path, destination: Path) -> None:
    if not source.is_file() or not checksum_file.is_file():
        raise RuntimeError("OPA binary or checksum file is missing")
    _validate_checksum_file(checksum_file)
    if _sha256_file(source) != OPA_BINARY_SHA256:
        raise RuntimeError("OPA binary digest does not match the reviewed release")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".opa-install-", dir=destination.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            with source.open("rb") as source_handle:
                shutil.copyfileobj(source_handle, temporary)
        temporary_path.chmod(0o500)
        if _sha256_file(temporary_path) != OPA_BINARY_SHA256:
            raise RuntimeError("OPA binary changed while it was being installed")
        _verify_version(temporary_path)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--checksum-file", required=True, type=Path)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    install(args.binary, args.checksum_file, args.destination)
    print(
        json.dumps(
            {
                "installed": True,
                "version": OPA_VERSION,
                "sha256": OPA_BINARY_SHA256,
                "mode": "0500",
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
