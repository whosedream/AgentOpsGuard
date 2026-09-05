#!/usr/bin/env python3
"""Install the reviewed Collector runtime outside Git after archive verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from install_cosign_current_runtime import (
    COSIGN_BINARY_SHA256,
    DEFAULT_DESTINATION as DEFAULT_COSIGN_BINARY,
    INSTALLED_TRUSTED_ROOT_NAME,
    TRUSTED_ROOT_SHA256,
)


COLLECTOR_VERSION = "0.160.0"
ARCHIVE_NAME = f"otelcol-contrib_{COLLECTOR_VERSION}_linux_amd64.tar.gz"
ARCHIVE_SHA256 = "7bb60c584c241c86261c2b8697cd3725dd8c56691f5ad5d98454eaa005b47b0c"
BINARY_SHA256 = "8524ac54f6e1d4d00d9ba5eea91daadec2ebc31e4da80db9c17eba2e859ecdd4"
SIGSTORE_BUNDLE_SHA256 = "337558f73b8bc9d6814ea66203e6e863822e40ac719f3af60ecb0be11de48f8a"
CERTIFICATE_IDENTITY = (
    "https://github.com/open-telemetry/opentelemetry-collector-releases/"
    ".github/workflows/base-release.yaml@refs/tags/v0.160.0"
)
CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_DESTINATION = (
    Path.home()
    / f".local/share/agentops-guard/otelcol-contrib/{COLLECTOR_VERSION}/otelcol-contrib"
)
DEFAULT_TRUSTED_ROOT = DEFAULT_COSIGN_BINARY.parent / INSTALLED_TRUSTED_ROOT_NAME
RELEASE_DIRECTORY_NAME = "release"
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_checksum_file(path: Path) -> None:
    checksum = path.read_text(encoding="utf-8-sig").strip().lower()
    if checksum != ARCHIVE_SHA256:
        raise RuntimeError("Collector checksum file does not match the reviewed release asset")


def _verify_version(path: Path) -> None:
    result = subprocess.run(
        (str(path), "--version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("installed Collector binary did not run")
    version_text = result.stdout.decode("utf-8", errors="replace")
    if version_text.strip() != f"otelcol-contrib version {COLLECTOR_VERSION}":
        raise RuntimeError("installed Collector binary reported an unexpected version")


def _verify_release_signature(
    *, archive: Path, bundle: Path, cosign: Path, trusted_root: Path
) -> None:
    if _sha256_file(cosign) != COSIGN_BINARY_SHA256:
        raise RuntimeError("Cosign binary digest does not match the reviewed release")
    if _sha256_file(trusted_root) != TRUSTED_ROOT_SHA256:
        raise RuntimeError("Sigstore trusted root digest does not match the reviewed root")
    if _sha256_file(bundle) != SIGSTORE_BUNDLE_SHA256:
        raise RuntimeError("Collector Sigstore bundle digest does not match the reviewed release")
    result = subprocess.run(
        (
            str(cosign),
            "verify-blob",
            "-t",
            "30s",
            "--trusted-root",
            str(trusted_root),
            "--bundle",
            str(bundle),
            "--certificate-identity",
            CERTIFICATE_IDENTITY,
            "--certificate-oidc-issuer",
            CERTIFICATE_OIDC_ISSUER,
            str(archive),
        ),
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TMPDIR": "/tmp"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=35,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Collector release signature or signing identity did not verify")


def _atomic_copy(source: Path, destination: Path, *, mode: int) -> None:
    temporary_path: Path | None = None
    try:
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}-install-", dir=destination.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            shutil.copyfileobj(source_handle, temporary, length=1024 * 1024)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(mode)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def install(
    archive: Path,
    checksum_file: Path,
    sigstore_bundle: Path,
    cosign: Path,
    trusted_root: Path,
    destination: Path,
) -> None:
    if not all(path.is_file() for path in (archive, checksum_file, sigstore_bundle, cosign, trusted_root)):
        raise RuntimeError("Collector release input or trusted verifier is missing")
    if any(path.is_symlink() for path in (archive, checksum_file, sigstore_bundle, cosign, trusted_root)):
        raise RuntimeError("Collector release inputs and trusted verifier must not be symbolic links")
    _validate_checksum_file(checksum_file)
    if _sha256_file(archive) != ARCHIVE_SHA256:
        raise RuntimeError("Collector archive digest does not match the reviewed release")
    if sigstore_bundle.stat().st_size > MAX_METADATA_BYTES:
        raise RuntimeError("Collector Sigstore bundle is too large")
    _verify_release_signature(
        archive=archive,
        bundle=sigstore_bundle,
        cosign=cosign,
        trusted_root=trusted_root,
    )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path: Path | None = None
    try:
        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            if {member.name for member in members} != {"README.md", "otelcol-contrib"}:
                raise RuntimeError("Collector archive contains unexpected paths")
            binary_member = source.getmember("otelcol-contrib")
            if not binary_member.isfile() or not 0 < binary_member.size <= MAX_BINARY_BYTES:
                raise RuntimeError("Collector archive binary is not a bounded regular file")
            binary = source.extractfile(binary_member)
            if binary is None:
                raise RuntimeError("Collector archive binary cannot be read")
            with tempfile.NamedTemporaryFile(
                prefix=".otelcol-install-", dir=destination.parent, delete=False
            ) as temporary:
                temporary_path = Path(temporary.name)
                while chunk := binary.read(1024 * 1024):
                    temporary.write(chunk)
        temporary_path.chmod(0o500)
        if _sha256_file(temporary_path) != BINARY_SHA256:
            raise RuntimeError("Collector binary digest does not match the reviewed release")
        _verify_version(temporary_path)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    release_directory = destination.parent / RELEASE_DIRECTORY_NAME
    release_directory.mkdir(mode=0o700, exist_ok=True)
    _atomic_copy(archive, release_directory / ARCHIVE_NAME, mode=0o400)
    _atomic_copy(checksum_file, release_directory / f"{ARCHIVE_NAME}.sha256", mode=0o400)
    _atomic_copy(
        sigstore_bundle,
        release_directory / f"{ARCHIVE_NAME}.sigstore.json",
        mode=0o400,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--checksum-file", required=True, type=Path)
    parser.add_argument("--sigstore-bundle", required=True, type=Path)
    parser.add_argument("--cosign", type=Path, default=DEFAULT_COSIGN_BINARY)
    parser.add_argument("--trusted-root", type=Path, default=DEFAULT_TRUSTED_ROOT)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    install(
        args.archive,
        args.checksum_file,
        args.sigstore_bundle,
        args.cosign,
        args.trusted_root,
        args.destination,
    )
    print(
        json.dumps(
            {
                "installed": True,
                "version": COLLECTOR_VERSION,
                "archive_sha256": ARCHIVE_SHA256,
                "binary_sha256": BINARY_SHA256,
                "sigstore_bundle_sha256": SIGSTORE_BUNDLE_SHA256,
                "signature_verified": True,
                "identity_exact_match": True,
                "issuer_exact_match": True,
                "mode": "0500",
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
