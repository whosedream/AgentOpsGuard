from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    script = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


installer = _load("install_otelcol_current_runtime")
verifier = _load("verify_otelcol_resilient_host_runtime")
cosign_installer = _load("install_cosign_current_runtime")


def test_collector_checksum_file_is_bound_to_reviewed_archive(tmp_path: Path):
    checksum = tmp_path / "collector.sha256"
    checksum.write_text(installer.ARCHIVE_SHA256, encoding="utf-8")
    installer._validate_checksum_file(checksum)

    for rejected in ("0" * 64, f"{installer.ARCHIVE_SHA256}  archive.tar.gz"):
        checksum.write_text(rejected, encoding="utf-8")
        with pytest.raises(RuntimeError, match="checksum file"):
            installer._validate_checksum_file(checksum)


def test_resilient_collector_config_uses_disk_queue_retry_and_loopback(tmp_path: Path):
    config = verifier._collector_config(
        receiver_port=14317,
        health_port=13133,
        backend_port=24317,
        queue_dir=tmp_path / "queue",
    )

    assert "endpoint: 127.0.0.1:14317" in config
    assert "endpoint: 127.0.0.1:24317" in config
    assert "endpoint: 127.0.0.1:13133" in config
    assert "storage: file_storage" in config
    assert "retry_on_failure:" in config
    assert "max_elapsed_time: 60s" in config
    assert "debug" not in config


def test_release_verification_uses_exact_identity_and_offline_root(monkeypatch, tmp_path: Path):
    archive = tmp_path / "collector.tar.gz"
    bundle = tmp_path / "collector.sigstore.json"
    cosign = tmp_path / "cosign"
    trusted_root = tmp_path / "trusted_root.json"
    archive.write_bytes(b"archive")
    bundle.write_bytes(b"bundle")
    cosign.write_bytes(b"cosign")
    trusted_root.write_bytes(b"root")

    digests = {
        cosign: installer.COSIGN_BINARY_SHA256,
        trusted_root: installer.TRUSTED_ROOT_SHA256,
        bundle: installer.SIGSTORE_BUNDLE_SHA256,
    }
    monkeypatch.setattr(installer, "_sha256_file", lambda path: digests[path])
    captured = {}

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Result()

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    installer._verify_release_signature(
        archive=archive,
        bundle=bundle,
        cosign=cosign,
        trusted_root=trusted_root,
    )

    command = captured["command"]
    assert "--trusted-root" in command
    assert "--certificate-identity" in command
    assert installer.CERTIFICATE_IDENTITY in command
    assert "--certificate-identity-regexp" not in command
    assert installer.CERTIFICATE_OIDC_ISSUER in command
    assert captured["kwargs"]["stdout"] is installer.subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] is installer.subprocess.DEVNULL


def test_cosign_release_is_digest_and_identity_pinned():
    assert cosign_installer.COSIGN_VERSION == "3.1.2"
    assert len(cosign_installer.COSIGN_BINARY_SHA256) == 64
    assert len(cosign_installer.COSIGN_BUNDLE_SHA256) == 64
    assert len(cosign_installer.COSIGN_KMS_BUNDLE_SHA256) == 64
    assert len(cosign_installer.ARTIFACT_KEY_SHA256) == 64
    assert len(cosign_installer.TRUSTED_ROOT_SHA256) == 64
    assert cosign_installer.COSIGN_CERTIFICATE_IDENTITY == (
        "keyless@projectsigstore.iam.gserviceaccount.com"
    )
    assert cosign_installer.COSIGN_CERTIFICATE_OIDC_ISSUER == "https://accounts.google.com"


def test_cosign_artifact_key_signature_is_verified_without_running_cosign(tmp_path: Path):
    import base64
    import hashlib
    import json

    binary = tmp_path / "cosign"
    binary.write_bytes(b"reviewed-cosign-binary")
    digest = hashlib.sha256(binary.read_bytes()).digest()
    private_key = ec.generate_private_key(ec.SECP256R1())
    artifact_key = tmp_path / "artifact.pub"
    artifact_key.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    bundle = tmp_path / "cosign-kms.sigstore.json"
    bundle.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(digest).decode(),
                    },
                    "signature": base64.b64encode(signature).decode(),
                },
            }
        ),
        encoding="utf-8",
    )

    cosign_installer._verify_artifact_key_signature(binary, bundle, artifact_key)
    binary.write_bytes(binary.read_bytes() + b"tampered")
    with pytest.raises(RuntimeError, match="artifact-key signature"):
        cosign_installer._verify_artifact_key_signature(binary, bundle, artifact_key)
