from __future__ import annotations

import base64
import hashlib
import importlib.util
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


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


installer = _load("install_minio_object_lock_runtime")


def _encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii").rstrip("=")


def test_minisign_verifier_checks_payload_key_id_and_trusted_comment(tmp_path: Path):
    binary = tmp_path / "minio"
    binary.write_bytes(b"reviewed-minio-binary")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    key_id = b"key-id-1"
    trusted_comment = "timestamp:1\tfilename:minio.RELEASE.test"
    payload_signature = private_key.sign(
        hashlib.blake2b(binary.read_bytes(), digest_size=64).digest()
    )
    comment_signature = private_key.sign(
        payload_signature + trusted_comment.encode("utf-8")
    )
    public_packet = b"Ed" + key_id + public_key
    signature_packet = b"ED" + key_id + payload_signature
    signature_file = tmp_path / "minio.minisig"
    signature_file.write_text(
        "\n".join(
            (
                "untrusted comment: signature from minisign secret key",
                _encoded(signature_packet),
                f"trusted comment: {trusted_comment}",
                _encoded(comment_signature),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    installer._verify_minisign(
        binary,
        signature_file,
        public_key_text=_encoded(public_packet),
        expected_trusted_comment=trusted_comment,
    )
    binary.write_bytes(binary.read_bytes() + b"tampered")
    with pytest.raises(RuntimeError, match="Minisign signature"):
        installer._verify_minisign(
            binary,
            signature_file,
            public_key_text=_encoded(public_packet),
            expected_trusted_comment=trusted_comment,
        )


def test_minio_release_is_version_digest_and_signature_pinned():
    assert installer.MINIO_VERSION == "RELEASE.2025-09-07T16-13-09Z"
    assert len(installer.MINIO_BINARY_SHA256) == 64
    assert len(installer.MINIO_SIGNATURE_SHA256) == 64
    assert installer.MINIO_MINISIGN_PUBLIC_KEY.startswith("RWT")
