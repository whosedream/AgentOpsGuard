#!/usr/bin/env python3
"""Verify pinned Cosign and Collector release provenance, including tamper rejection."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from install_cosign_current_runtime import (
    ARTIFACT_KEY_SHA256,
    COSIGN_BINARY_SHA256,
    COSIGN_BUNDLE_SHA256,
    COSIGN_CERTIFICATE_IDENTITY,
    COSIGN_CERTIFICATE_OIDC_ISSUER,
    COSIGN_KMS_BUNDLE_SHA256,
    COSIGN_VERSION,
    DEFAULT_DESTINATION as COSIGN_BINARY,
    INSTALLED_ARTIFACT_KEY_NAME,
    INSTALLED_BUNDLE_NAME,
    INSTALLED_KMS_BUNDLE_NAME,
    INSTALLED_TRUSTED_ROOT_NAME,
    TRUSTED_ROOT_SHA256,
    _verify_artifact_key_signature,
    _verify_kms_bundle,
)
from install_otelcol_current_runtime import (
    ARCHIVE_NAME,
    ARCHIVE_SHA256,
    BINARY_SHA256,
    CERTIFICATE_IDENTITY,
    CERTIFICATE_OIDC_ISSUER,
    COLLECTOR_VERSION,
    DEFAULT_DESTINATION as COLLECTOR_BINARY,
    RELEASE_DIRECTORY_NAME,
    SIGSTORE_BUNDLE_SHA256,
)


COSIGN_BUNDLE = COSIGN_BINARY.parent / INSTALLED_BUNDLE_NAME
COSIGN_KMS_BUNDLE = COSIGN_BINARY.parent / INSTALLED_KMS_BUNDLE_NAME
COSIGN_ARTIFACT_KEY = COSIGN_BINARY.parent / INSTALLED_ARTIFACT_KEY_NAME
TRUSTED_ROOT = COSIGN_BINARY.parent / INSTALLED_TRUSTED_ROOT_NAME
COLLECTOR_RELEASE_DIRECTORY = COLLECTOR_BINARY.parent / RELEASE_DIRECTORY_NAME
COLLECTOR_ARCHIVE = COLLECTOR_RELEASE_DIRECTORY / ARCHIVE_NAME
COLLECTOR_CHECKSUM = COLLECTOR_RELEASE_DIRECTORY / f"{ARCHIVE_NAME}.sha256"
COLLECTOR_BUNDLE = COLLECTOR_RELEASE_DIRECTORY / f"{ARCHIVE_NAME}.sigstore.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_cosign(
    *, blob: Path, bundle: Path, identity: str, issuer: str
) -> subprocess.CompletedProcess[bytes]:
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
            identity,
            "--certificate-oidc-issuer",
            issuer,
            str(blob),
        ),
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TMPDIR": "/tmp"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=35,
        check=False,
    )


def _verify_versions() -> None:
    cosign = subprocess.run(
        (str(COSIGN_BINARY), "version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    cosign_output = cosign.stdout.decode("utf-8", errors="replace")
    if cosign.returncode != 0 or f"GitVersion:    v{COSIGN_VERSION}" not in cosign_output:
        raise RuntimeError("pinned Cosign runtime reported an unexpected version")
    collector = subprocess.run(
        (str(COLLECTOR_BINARY), "--version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    if collector.returncode != 0 or collector.stdout.decode("utf-8", errors="replace").strip() != (
        f"otelcol-contrib version {COLLECTOR_VERSION}"
    ):
        raise RuntimeError("pinned Collector runtime reported an unexpected version")


def _verify_archive_binary() -> None:
    with tarfile.open(COLLECTOR_ARCHIVE, "r:gz") as source:
        names = {member.name for member in source.getmembers()}
        if names != {"README.md", "otelcol-contrib"}:
            raise RuntimeError("stored Collector archive contains unexpected paths")
        binary = source.extractfile("otelcol-contrib")
        if binary is None:
            raise RuntimeError("stored Collector binary cannot be read")
        digest = hashlib.sha256()
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != BINARY_SHA256 or _sha256_file(COLLECTOR_BINARY) != BINARY_SHA256:
        raise RuntimeError("installed Collector does not match the signed archive")


def _verify_tamper_rejection() -> None:
    with tempfile.TemporaryDirectory(prefix="agentops-sigstore-negative-") as temporary:
        tampered = Path(temporary) / ARCHIVE_NAME
        shutil.copyfile(COLLECTOR_ARCHIVE, tampered)
        with tampered.open("r+b") as handle:
            first = handle.read(1)
            if not first:
                raise RuntimeError("stored Collector archive is empty")
            handle.seek(0)
            handle.write(bytes((first[0] ^ 0x01,)))
            handle.flush()
            os.fsync(handle.fileno())
        result = _run_cosign(
            blob=tampered,
            bundle=COLLECTOR_BUNDLE,
            identity=CERTIFICATE_IDENTITY,
            issuer=CERTIFICATE_OIDC_ISSUER,
        )
        if result.returncode == 0:
            raise RuntimeError("Cosign accepted a one-byte-tampered Collector archive")


def verify() -> dict[str, object]:
    expected = (
        (COSIGN_BINARY, COSIGN_BINARY_SHA256, "Cosign binary"),
        (COSIGN_BUNDLE, COSIGN_BUNDLE_SHA256, "Cosign bundle"),
        (COSIGN_KMS_BUNDLE, COSIGN_KMS_BUNDLE_SHA256, "Cosign artifact-key bundle"),
        (COSIGN_ARTIFACT_KEY, ARTIFACT_KEY_SHA256, "Cosign artifact public key"),
        (TRUSTED_ROOT, TRUSTED_ROOT_SHA256, "Sigstore trusted root"),
        (COLLECTOR_ARCHIVE, ARCHIVE_SHA256, "Collector archive"),
        (COLLECTOR_BUNDLE, SIGSTORE_BUNDLE_SHA256, "Collector bundle"),
        (COLLECTOR_BINARY, BINARY_SHA256, "Collector binary"),
    )
    for path, digest, label in expected:
        if not path.is_file() or path.is_symlink() or _sha256_file(path) != digest:
            raise RuntimeError(f"{label} is missing, linked, or has the wrong digest")
    if COLLECTOR_CHECKSUM.read_text(encoding="utf-8-sig").strip().lower() != ARCHIVE_SHA256:
        raise RuntimeError("stored Collector checksum file does not match the reviewed release")

    _verify_versions()
    _verify_artifact_key_signature(COSIGN_BINARY, COSIGN_KMS_BUNDLE, COSIGN_ARTIFACT_KEY)
    _verify_kms_bundle(
        COSIGN_BINARY, COSIGN_KMS_BUNDLE, COSIGN_ARTIFACT_KEY, TRUSTED_ROOT
    )
    if _run_cosign(
        blob=COSIGN_BINARY,
        bundle=COSIGN_BUNDLE,
        identity=COSIGN_CERTIFICATE_IDENTITY,
        issuer=COSIGN_CERTIFICATE_OIDC_ISSUER,
    ).returncode != 0:
        raise RuntimeError("pinned Cosign release signature did not verify")
    if _run_cosign(
        blob=COLLECTOR_ARCHIVE,
        bundle=COLLECTOR_BUNDLE,
        identity=CERTIFICATE_IDENTITY,
        issuer=CERTIFICATE_OIDC_ISSUER,
    ).returncode != 0:
        raise RuntimeError("pinned Collector release signature did not verify")
    _verify_archive_binary()
    _verify_tamper_rejection()

    return {
        "cosign_version": COSIGN_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "checks": {
            "cosign_binary_digest_verified": True,
            "cosign_artifact_key_signature_verified_without_cosign": True,
            "cosign_artifact_key_transparency_proof_verified": True,
            "cosign_release_signature_verified": True,
            "collector_archive_digest_verified": True,
            "collector_release_signature_verified": True,
            "certificate_identities_are_exact": True,
            "oidc_issuers_are_exact": True,
            "transparency_log_proofs_verified_offline": True,
            "installed_collector_matches_signed_archive": True,
            "one_byte_payload_tamper_rejected": True,
        },
        "limits": {
            "collector_container_image_signature_verified": False,
            "private_registry_policy_verified": False,
            "ci_workflow_run_verified": False,
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
        raise RuntimeError("signed release verification failed")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
