#!/usr/bin/env python3
"""Install the reviewed Cosign runtime outside Git after offline verification."""

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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


COSIGN_VERSION = "3.1.2"
COSIGN_BINARY_SHA256 = "f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf"
COSIGN_BUNDLE_SHA256 = "fdaa1c168d67041cd0d8f5782f8136ac5d148827b6911ba8bb577cbc7e13de2c"
COSIGN_KMS_BUNDLE_SHA256 = "5a16755e5fd4c048527f26bf0fb4c8c9731fca3cf35156b945aa222d220ca7ef"
ARTIFACT_KEY_SHA256 = "59ebf97a9850aecec4bc39c1f5c1dc46e6490a6b5fd2a6cacdcac0c3a6fc4cbf"
TRUSTED_ROOT_SHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
COSIGN_CERTIFICATE_IDENTITY = "keyless@projectsigstore.iam.gserviceaccount.com"
COSIGN_CERTIFICATE_OIDC_ISSUER = "https://accounts.google.com"
DEFAULT_DESTINATION = (
    Path.home() / f".local/share/agentops-guard/cosign/{COSIGN_VERSION}/cosign"
)
INSTALLED_BUNDLE_NAME = "cosign-linux-amd64.sigstore.json"
INSTALLED_KMS_BUNDLE_NAME = "cosign-linux-amd64-kms.sigstore.json"
INSTALLED_ARTIFACT_KEY_NAME = "artifact.pub"
INSTALLED_TRUSTED_ROOT_NAME = "trusted_root.json"
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_regular_file(path: Path, *, maximum_bytes: int, label: str) -> None:
    if path.is_symlink():
        raise RuntimeError(f"{label} must not be a symbolic link")
    try:
        file_stat = path.stat()
    except FileNotFoundError as error:
        raise RuntimeError(f"{label} is missing") from error
    if not stat.S_ISREG(file_stat.st_mode) or not 0 < file_stat.st_size <= maximum_bytes:
        raise RuntimeError(f"{label} is not a bounded regular file")


def _verify_version(path: Path) -> None:
    result = subprocess.run(
        (str(path), "version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Cosign binary did not run")
    output = result.stdout.decode("utf-8", errors="replace")
    if f"GitVersion:    v{COSIGN_VERSION}" not in output or "Platform:      linux/amd64" not in output:
        raise RuntimeError("Cosign binary reported an unexpected version or platform")


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _verify_artifact_key_signature(binary: Path, kms_bundle: Path, artifact_key: Path) -> None:
    try:
        bundle = json.loads(
            kms_bundle.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
        )
        if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
            raise ValueError("unexpected bundle media type")
        message_signature = bundle["messageSignature"]
        message_digest = message_signature["messageDigest"]
        if message_digest["algorithm"] != "SHA2_256":
            raise ValueError("unexpected digest algorithm")
        binary_digest = bytes.fromhex(_sha256_file(binary))
        if base64.b64decode(message_digest["digest"], validate=True) != binary_digest:
            raise ValueError("bundle digest does not match the Cosign binary")
        signature = base64.b64decode(message_signature["signature"], validate=True)
        public_key = serialization.load_pem_public_key(artifact_key.read_bytes())
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError("artifact key is not the reviewed P-256 public key type")
        public_key.verify(
            signature,
            binary_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError) as error:
        raise RuntimeError("Cosign artifact-key signature did not verify") from error


def _verify_kms_bundle(
    binary: Path, kms_bundle: Path, artifact_key: Path, trusted_root: Path
) -> None:
    result = subprocess.run(
        (
            str(binary),
            "verify-blob",
            "-t",
            "30s",
            "--trusted-root",
            str(trusted_root),
            "--bundle",
            str(kms_bundle),
            "--key",
            str(artifact_key),
            str(binary),
        ),
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TMPDIR": "/tmp"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=35,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Cosign artifact-key bundle or transparency proof did not verify")


def _verify_self_signature(binary: Path, bundle: Path, trusted_root: Path) -> None:
    result = subprocess.run(
        (
            str(binary),
            "verify-blob",
            "-t",
            "30s",
            "--trusted-root",
            str(trusted_root),
            "--bundle",
            str(bundle),
            "--certificate-identity",
            COSIGN_CERTIFICATE_IDENTITY,
            "--certificate-oidc-issuer",
            COSIGN_CERTIFICATE_OIDC_ISSUER,
            str(binary),
        ),
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TMPDIR": "/tmp"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=35,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Cosign release signature or signing identity did not verify")


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
    binary: Path,
    bundle: Path,
    kms_bundle: Path,
    artifact_key: Path,
    trusted_root: Path,
    destination: Path,
) -> None:
    _validate_regular_file(binary, maximum_bytes=MAX_BINARY_BYTES, label="Cosign binary")
    _validate_regular_file(bundle, maximum_bytes=MAX_METADATA_BYTES, label="Cosign bundle")
    _validate_regular_file(
        kms_bundle, maximum_bytes=MAX_METADATA_BYTES, label="Cosign artifact-key bundle"
    )
    _validate_regular_file(
        artifact_key, maximum_bytes=MAX_METADATA_BYTES, label="Cosign artifact public key"
    )
    _validate_regular_file(
        trusted_root, maximum_bytes=MAX_METADATA_BYTES, label="Sigstore trusted root"
    )
    expected_digests = (
        (binary, COSIGN_BINARY_SHA256, "Cosign binary"),
        (bundle, COSIGN_BUNDLE_SHA256, "Cosign bundle"),
        (kms_bundle, COSIGN_KMS_BUNDLE_SHA256, "Cosign artifact-key bundle"),
        (artifact_key, ARTIFACT_KEY_SHA256, "Cosign artifact public key"),
        (trusted_root, TRUSTED_ROOT_SHA256, "Sigstore trusted root"),
    )
    for path, expected_digest, label in expected_digests:
        if _sha256_file(path) != expected_digest:
            raise RuntimeError(f"{label} digest does not match the reviewed release")
    _verify_artifact_key_signature(binary, kms_bundle, artifact_key)
    _verify_version(binary)
    _verify_kms_bundle(binary, kms_bundle, artifact_key, trusted_root)
    _verify_self_signature(binary, bundle, trusted_root)

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    installed_bundle = destination.parent / INSTALLED_BUNDLE_NAME
    installed_kms_bundle = destination.parent / INSTALLED_KMS_BUNDLE_NAME
    installed_artifact_key = destination.parent / INSTALLED_ARTIFACT_KEY_NAME
    installed_trusted_root = destination.parent / INSTALLED_TRUSTED_ROOT_NAME
    _atomic_copy(bundle, installed_bundle, mode=0o400)
    _atomic_copy(kms_bundle, installed_kms_bundle, mode=0o400)
    _atomic_copy(artifact_key, installed_artifact_key, mode=0o400)
    _atomic_copy(trusted_root, installed_trusted_root, mode=0o400)
    _atomic_copy(binary, destination, mode=0o500)

    if _sha256_file(destination) != COSIGN_BINARY_SHA256:
        raise RuntimeError("installed Cosign binary digest changed during installation")
    _verify_artifact_key_signature(destination, installed_kms_bundle, installed_artifact_key)
    _verify_version(destination)
    _verify_kms_bundle(
        destination, installed_kms_bundle, installed_artifact_key, installed_trusted_root
    )
    _verify_self_signature(destination, installed_bundle, installed_trusted_root)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--kms-bundle", required=True, type=Path)
    parser.add_argument("--artifact-key", required=True, type=Path)
    parser.add_argument("--trusted-root", required=True, type=Path)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    install(
        args.binary,
        args.bundle,
        args.kms_bundle,
        args.artifact_key,
        args.trusted_root,
        args.destination,
    )
    print(
        json.dumps(
            {
                "installed": True,
                "version": COSIGN_VERSION,
                "binary_sha256": COSIGN_BINARY_SHA256,
                "bundle_sha256": COSIGN_BUNDLE_SHA256,
                "kms_bundle_sha256": COSIGN_KMS_BUNDLE_SHA256,
                "artifact_key_sha256": ARTIFACT_KEY_SHA256,
                "trusted_root_sha256": TRUSTED_ROOT_SHA256,
                "artifact_key_signature_verified": True,
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
