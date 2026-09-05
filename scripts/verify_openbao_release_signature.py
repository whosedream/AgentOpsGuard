#!/usr/bin/env python3
"""Reverify the pinned OpenBao release, installed binary, and tamper rejection."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from install_cosign_current_runtime import (
    COSIGN_BINARY_SHA256,
    DEFAULT_DESTINATION as COSIGN_BINARY,
    INSTALLED_TRUSTED_ROOT_NAME,
    TRUSTED_ROOT_SHA256,
)
from install_openbao_current_runtime import (
    ARCHIVE_BUNDLE_SHA256,
    ARCHIVE_MEMBERS,
    ARCHIVE_NAME,
    ARCHIVE_SHA256,
    BINARY_SHA256,
    CERTIFICATE_IDENTITY,
    CERTIFICATE_OIDC_ISSUER,
    CHECKSUMS_BUNDLE_SHA256,
    CHECKSUMS_SHA256,
    DEFAULT_DESTINATION as OPENBAO_BINARY,
    DEFAULT_RELEASE_DIRECTORY,
    MAX_ARCHIVE_BYTES,
    MAX_BINARY_BYTES,
    MAX_METADATA_BYTES,
    OPENBAO_BUILD_TIME,
    OPENBAO_COMMIT,
    OPENBAO_VERSION,
    _archive_binary,
    _validate_checksums,
    _verify_version,
)


TRUSTED_ROOT = COSIGN_BINARY.parent / INSTALLED_TRUSTED_ROOT_NAME
OPENBAO_ARCHIVE = DEFAULT_RELEASE_DIRECTORY / ARCHIVE_NAME
OPENBAO_CHECKSUMS = DEFAULT_RELEASE_DIRECTORY / "checksums.txt"
OPENBAO_CHECKSUMS_BUNDLE = DEFAULT_RELEASE_DIRECTORY / "checksums.txt.sigstore.json"
OPENBAO_ARCHIVE_BUNDLE = DEFAULT_RELEASE_DIRECTORY / f"{ARCHIVE_NAME}.sigstore.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_cosign(blob: Path, bundle: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (
            str(COSIGN_BINARY),
            "verify-blob",
            "-t",
            "30s",
            "--trusted-root",
            str(TRUSTED_ROOT),
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


def _verify_archive_binary() -> None:
    source, binary = _archive_binary(OPENBAO_ARCHIVE)
    try:
        digest = hashlib.sha256()
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    finally:
        source.close()
    if digest.hexdigest() != BINARY_SHA256 or _sha256_file(OPENBAO_BINARY) != BINARY_SHA256:
        raise RuntimeError("installed OpenBao binary does not match the signed archive")


def _mutate_first_byte(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)
    with destination.open("r+b") as handle:
        first = handle.read(1)
        if not first:
            raise RuntimeError("OpenBao release file is empty")
        handle.seek(0)
        handle.write(bytes((first[0] ^ 0x01,)))
        handle.flush()
        os.fsync(handle.fileno())


def _verify_tamper_rejection() -> None:
    with tempfile.TemporaryDirectory(prefix="agentops-openbao-signature-negative-") as temporary:
        temporary_path = Path(temporary)
        tampered_archive = temporary_path / ARCHIVE_NAME
        _mutate_first_byte(OPENBAO_ARCHIVE, tampered_archive)
        if _run_cosign(tampered_archive, OPENBAO_ARCHIVE_BUNDLE).returncode == 0:
            raise RuntimeError("Cosign accepted a one-byte-tampered OpenBao archive")
        tampered_checksums = temporary_path / "checksums.txt"
        _mutate_first_byte(OPENBAO_CHECKSUMS, tampered_checksums)
        if _run_cosign(tampered_checksums, OPENBAO_CHECKSUMS_BUNDLE).returncode == 0:
            raise RuntimeError("Cosign accepted a one-byte-tampered OpenBao checksum manifest")


def verify() -> dict[str, object]:
    expected = (
        (COSIGN_BINARY, COSIGN_BINARY_SHA256, MAX_BINARY_BYTES, "Cosign binary"),
        (TRUSTED_ROOT, TRUSTED_ROOT_SHA256, MAX_METADATA_BYTES, "Sigstore trusted root"),
        (OPENBAO_ARCHIVE, ARCHIVE_SHA256, MAX_ARCHIVE_BYTES, "OpenBao archive"),
        (OPENBAO_CHECKSUMS, CHECKSUMS_SHA256, MAX_METADATA_BYTES, "checksum manifest"),
        (
            OPENBAO_CHECKSUMS_BUNDLE,
            CHECKSUMS_BUNDLE_SHA256,
            MAX_METADATA_BYTES,
            "checksum bundle",
        ),
        (
            OPENBAO_ARCHIVE_BUNDLE,
            ARCHIVE_BUNDLE_SHA256,
            MAX_METADATA_BYTES,
            "archive bundle",
        ),
        (OPENBAO_BINARY, BINARY_SHA256, MAX_BINARY_BYTES, "OpenBao binary"),
    )
    for path, digest, maximum, label in expected:
        if (
            not path.is_file()
            or path.is_symlink()
            or not 0 < path.stat().st_size <= maximum
            or _sha256_file(path) != digest
        ):
            raise RuntimeError(f"{label} is missing, linked, oversized, or has the wrong digest")

    if _run_cosign(OPENBAO_CHECKSUMS, OPENBAO_CHECKSUMS_BUNDLE).returncode != 0:
        raise RuntimeError("OpenBao checksum manifest signature did not verify")
    _validate_checksums(OPENBAO_CHECKSUMS)
    if _run_cosign(OPENBAO_ARCHIVE, OPENBAO_ARCHIVE_BUNDLE).returncode != 0:
        raise RuntimeError("OpenBao archive signature did not verify")
    _verify_version(OPENBAO_BINARY)
    _verify_archive_binary()
    _verify_tamper_rejection()

    return {
        "openbao_version": OPENBAO_VERSION,
        "openbao_commit": OPENBAO_COMMIT,
        "openbao_build_time": OPENBAO_BUILD_TIME,
        "archive_members": sorted(ARCHIVE_MEMBERS),
        "checks": {
            "cosign_binary_digest_verified": True,
            "trusted_root_digest_verified": True,
            "checksum_manifest_signature_verified": True,
            "checksum_manifest_binds_archive": True,
            "archive_signature_verified": True,
            "certificate_identity_exact": True,
            "oidc_issuer_exact": True,
            "transparency_log_proofs_verified_offline": True,
            "installed_binary_matches_signed_archive": True,
            "archive_tamper_rejected": True,
            "checksum_manifest_tamper_rejected": True,
        },
        "limits": {
            "production_container_image_signature_verified": False,
            "private_registry_policy_verified": False,
            "hosted_ci_run_verified": False,
        },
        "privacy": {
            "captures_artifact_content": False,
            "captures_signature_or_certificate_content": False,
            "captures_environment_values": False,
        },
    }


def main() -> None:
    result = verify()
    if not all(result["checks"].values()):
        raise RuntimeError("OpenBao signed release verification failed")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
