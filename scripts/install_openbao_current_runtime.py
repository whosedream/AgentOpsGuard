#!/usr/bin/env python3
"""Install the signer-verified OpenBao runtime and retain its release evidence."""

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


OPENBAO_VERSION = "2.6.1"
OPENBAO_COMMIT = "ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f"
OPENBAO_BUILD_TIME = "2026-07-22T14:22:20Z"
ARCHIVE_NAME = f"openbao_{OPENBAO_VERSION}_linux_amd64.tar.gz"
ARCHIVE_SHA256 = "ca8d836eb3a5c80407e45e762300b64e7138c419e78826955f2e4ba4ce6d8a6b"
BINARY_SHA256 = "736b8ecf354fda6b2af62e4ae064f12fe6c52d7db8425b9c6de22f286a5485ec"
CHECKSUMS_SHA256 = "e6985523c63e527dc4f25f0121d53fc08c7e79bed955bb28d747d6724bc3535b"
CHECKSUMS_BUNDLE_SHA256 = "a8e8a2f337c9b9206dfa89be53c05323d7d3c84d1e4fa6fc4067ff8e703718bc"
ARCHIVE_BUNDLE_SHA256 = "d289f620791964fac6acecda351526785a3a24620d5d3d377164a97bb67977ae"
CERTIFICATE_IDENTITY = (
    "https://github.com/openbao/openbao/.github/workflows/"
    "release.yml@refs/heads/release/2.6.x"
)
CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_DESTINATION = Path.home() / ".local/bin/bao"
DEFAULT_RELEASE_DIRECTORY = (
    Path.home() / f".local/share/agentops-guard/openbao/{OPENBAO_VERSION}/release"
)
DEFAULT_TRUSTED_ROOT = DEFAULT_COSIGN_BINARY.parent / INSTALLED_TRUSTED_ROOT_NAME
ARCHIVE_MEMBERS = {"CHANGELOG.md", "LICENSE", "README.md", "bao"}
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_checksums(path: Path) -> None:
    matches = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == ARCHIVE_NAME:
            matches.append(parts[0].lower())
    if matches != [ARCHIVE_SHA256]:
        raise RuntimeError("OpenBao checksum manifest does not bind the reviewed archive")


def _verify_signature(
    *, blob: Path, bundle: Path, cosign: Path, trusted_root: Path
) -> None:
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
            str(blob),
        ),
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TMPDIR": "/tmp"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=35,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("OpenBao release signature or exact signer identity did not verify")


def _archive_binary(archive: Path):
    source = tarfile.open(archive, "r:gz")
    try:
        members = source.getmembers()
        if {member.name for member in members} != ARCHIVE_MEMBERS:
            raise RuntimeError("OpenBao archive contains unexpected paths")
        if any(not member.isfile() for member in members):
            raise RuntimeError("OpenBao archive contains a non-regular member")
        binary_member = source.getmember("bao")
        if not 0 < binary_member.size <= MAX_BINARY_BYTES:
            raise RuntimeError("OpenBao archive binary size is invalid")
        binary = source.extractfile(binary_member)
        if binary is None:
            raise RuntimeError("OpenBao archive binary cannot be read")
        return source, binary
    except Exception:
        source.close()
        raise


def _verify_version(binary: Path) -> None:
    result = subprocess.run(
        (str(binary), "version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    expected = (
        f"OpenBao v{OPENBAO_VERSION} ({OPENBAO_COMMIT}), "
        f"committed {OPENBAO_BUILD_TIME}"
    )
    if result.returncode != 0 or result.stdout.decode("utf-8", errors="replace").strip() != expected:
        raise RuntimeError("installed OpenBao binary reported an unexpected release")


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
    *,
    archive: Path,
    checksums: Path,
    checksums_bundle: Path,
    archive_bundle: Path,
    cosign: Path,
    trusted_root: Path,
    destination: Path,
    release_directory: Path,
) -> None:
    inputs = (archive, checksums, checksums_bundle, archive_bundle, cosign, trusted_root)
    if not all(path.is_file() for path in inputs):
        raise RuntimeError("OpenBao release input or trusted verifier is missing")
    if any(path.is_symlink() for path in inputs):
        raise RuntimeError("OpenBao release inputs and trusted verifier must not be symbolic links")
    expected = (
        (archive, ARCHIVE_SHA256, MAX_ARCHIVE_BYTES, "archive"),
        (checksums, CHECKSUMS_SHA256, MAX_METADATA_BYTES, "checksum manifest"),
        (checksums_bundle, CHECKSUMS_BUNDLE_SHA256, MAX_METADATA_BYTES, "checksum bundle"),
        (archive_bundle, ARCHIVE_BUNDLE_SHA256, MAX_METADATA_BYTES, "archive bundle"),
        (cosign, COSIGN_BINARY_SHA256, MAX_BINARY_BYTES, "Cosign binary"),
        (trusted_root, TRUSTED_ROOT_SHA256, MAX_METADATA_BYTES, "Sigstore trusted root"),
    )
    for path, digest, maximum, label in expected:
        if not 0 < path.stat().st_size <= maximum or _sha256_file(path) != digest:
            raise RuntimeError(f"OpenBao {label} does not match the reviewed release")

    _verify_signature(
        blob=checksums,
        bundle=checksums_bundle,
        cosign=cosign,
        trusted_root=trusted_root,
    )
    _validate_checksums(checksums)
    _verify_signature(
        blob=archive,
        bundle=archive_bundle,
        cosign=cosign,
        trusted_root=trusted_root,
    )

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path: Path | None = None
    source, binary = _archive_binary(archive)
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".openbao-install-", dir=destination.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            while chunk := binary.read(1024 * 1024):
                temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(0o500)
        if _sha256_file(temporary_path) != BINARY_SHA256:
            raise RuntimeError("OpenBao binary does not match the signed archive")
        _verify_version(temporary_path)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        source.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    release_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    _atomic_copy(archive, release_directory / ARCHIVE_NAME, mode=0o400)
    _atomic_copy(checksums, release_directory / "checksums.txt", mode=0o400)
    _atomic_copy(
        checksums_bundle,
        release_directory / "checksums.txt.sigstore.json",
        mode=0o400,
    )
    _atomic_copy(
        archive_bundle,
        release_directory / f"{ARCHIVE_NAME}.sigstore.json",
        mode=0o400,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--checksums-bundle", required=True, type=Path)
    parser.add_argument("--archive-bundle", required=True, type=Path)
    parser.add_argument("--cosign", type=Path, default=DEFAULT_COSIGN_BINARY)
    parser.add_argument("--trusted-root", type=Path, default=DEFAULT_TRUSTED_ROOT)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument(
        "--release-directory",
        type=Path,
        default=DEFAULT_RELEASE_DIRECTORY,
    )
    args = parser.parse_args()
    install(
        archive=args.archive,
        checksums=args.checksums,
        checksums_bundle=args.checksums_bundle,
        archive_bundle=args.archive_bundle,
        cosign=args.cosign,
        trusted_root=args.trusted_root,
        destination=args.destination,
        release_directory=args.release_directory,
    )
    print(
        json.dumps(
            {
                "installed": True,
                "version": OPENBAO_VERSION,
                "archive_sha256": ARCHIVE_SHA256,
                "binary_sha256": BINARY_SHA256,
                "checksum_manifest_signature_verified": True,
                "archive_signature_verified": True,
                "identity_exact_match": True,
                "issuer_exact_match": True,
                "mode": "0500",
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
