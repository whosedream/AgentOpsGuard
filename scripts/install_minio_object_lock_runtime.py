#!/usr/bin/env python3
"""Install a reviewed MinIO runtime outside Git for local Object Lock verification."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MINIO_VERSION = "RELEASE.2025-09-07T16-13-09Z"
MINIO_BINARY_SHA256 = "7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f"
MINIO_SIGNATURE_SHA256 = "d71cf680e1de21ae4a71d8d6ff2c80d6f8b07cbe8a9e00e157ef40be213fd47f"
MINIO_MINISIGN_PUBLIC_KEY = "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"
EXPECTED_TRUSTED_COMMENT = f"timestamp:1757267687\tfilename:minio.{MINIO_VERSION}"
DEFAULT_DESTINATION = (
    Path.home() / f".local/share/agentops-guard/minio/{MINIO_VERSION}/minio"
)
INSTALLED_SIGNATURE_NAME = "minio.minisig"
INSTALLED_CHECKSUM_NAME = "minio.sha256sum"
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _blake2b_file(path: Path) -> bytes:
    digest = hashlib.blake2b(digest_size=64)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def _decode_base64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def _verify_minisign(
    binary: Path,
    signature_file: Path,
    *,
    public_key_text: str = MINIO_MINISIGN_PUBLIC_KEY,
    expected_trusted_comment: str = EXPECTED_TRUSTED_COMMENT,
) -> None:
    try:
        lines = signature_file.read_text(encoding="utf-8").splitlines()
        if len(lines) != 4:
            raise ValueError("signature file must contain exactly four lines")
        if lines[0] != "untrusted comment: signature from minisign secret key":
            raise ValueError("unexpected untrusted comment")
        prefix = "trusted comment: "
        if not lines[2].startswith(prefix):
            raise ValueError("trusted comment is missing")
        trusted_comment = lines[2].removeprefix(prefix)
        if trusted_comment != expected_trusted_comment:
            raise ValueError("trusted release comment does not match the pinned release")

        public_packet = _decode_base64(public_key_text)
        signature_packet = _decode_base64(lines[1])
        comment_signature = _decode_base64(lines[3])
        if len(public_packet) != 42 or public_packet[:2] != b"Ed":
            raise ValueError("unexpected Minisign public-key packet")
        if len(signature_packet) != 74 or signature_packet[:2] != b"ED":
            raise ValueError("Minisign signature must use the prehashed format")
        if len(comment_signature) != 64 or public_packet[2:10] != signature_packet[2:10]:
            raise ValueError("Minisign key identity does not match")

        public_key = Ed25519PublicKey.from_public_bytes(public_packet[10:])
        detached_signature = signature_packet[10:]
        public_key.verify(detached_signature, _blake2b_file(binary))
        public_key.verify(
            comment_signature,
            detached_signature + trusted_comment.encode("utf-8"),
        )
    except (InvalidSignature, OSError, UnicodeError, ValueError) as error:
        raise RuntimeError("MinIO Minisign signature did not verify") from error


def _validate_regular_file(path: Path, *, maximum_bytes: int, label: str) -> None:
    if path.is_symlink():
        raise RuntimeError(f"{label} must not be a symbolic link")
    try:
        file_stat = path.stat()
    except FileNotFoundError as error:
        raise RuntimeError(f"{label} is missing") from error
    if not stat.S_ISREG(file_stat.st_mode) or not 0 < file_stat.st_size <= maximum_bytes:
        raise RuntimeError(f"{label} is not a bounded regular file")


def _validate_checksum(checksum_file: Path) -> None:
    expected = f"{MINIO_BINARY_SHA256} minio.{MINIO_VERSION}"
    if checksum_file.read_text(encoding="utf-8-sig").strip() != expected:
        raise RuntimeError("MinIO checksum file does not match the pinned release")


def _verify_version(binary: Path) -> None:
    result = subprocess.run(
        (str(binary), "--version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    output = result.stdout.decode("utf-8", errors="replace")
    if (
        result.returncode != 0
        or not output.startswith(f"minio version {MINIO_VERSION} ")
        or "linux/amd64" not in output
    ):
        raise RuntimeError("MinIO binary reported an unexpected version or platform")


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


def install(binary: Path, checksum_file: Path, signature_file: Path, destination: Path) -> None:
    _validate_regular_file(binary, maximum_bytes=MAX_BINARY_BYTES, label="MinIO binary")
    _validate_regular_file(
        checksum_file, maximum_bytes=MAX_METADATA_BYTES, label="MinIO checksum"
    )
    _validate_regular_file(
        signature_file, maximum_bytes=MAX_METADATA_BYTES, label="MinIO signature"
    )
    _validate_checksum(checksum_file)
    if _sha256_file(binary) != MINIO_BINARY_SHA256:
        raise RuntimeError("MinIO binary digest does not match the pinned release")
    if _sha256_file(signature_file) != MINIO_SIGNATURE_SHA256:
        raise RuntimeError("MinIO signature digest does not match the pinned release")
    _verify_minisign(binary, signature_file)
    _verify_version(binary)

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    installed_checksum = destination.parent / INSTALLED_CHECKSUM_NAME
    installed_signature = destination.parent / INSTALLED_SIGNATURE_NAME
    _atomic_copy(checksum_file, installed_checksum, mode=0o400)
    _atomic_copy(signature_file, installed_signature, mode=0o400)
    _atomic_copy(binary, destination, mode=0o500)
    if _sha256_file(destination) != MINIO_BINARY_SHA256:
        raise RuntimeError("installed MinIO binary digest changed during installation")
    _verify_minisign(destination, installed_signature)
    _verify_version(destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--checksum-file", required=True, type=Path)
    parser.add_argument("--signature-file", required=True, type=Path)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    install(args.binary, args.checksum_file, args.signature_file, args.destination)
    print(
        json.dumps(
            {
                "installed": True,
                "version": MINIO_VERSION,
                "binary_sha256": MINIO_BINARY_SHA256,
                "signature_sha256": MINIO_SIGNATURE_SHA256,
                "minisign_verified": True,
                "mode": "0500",
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
