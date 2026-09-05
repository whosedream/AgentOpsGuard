from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

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


installer = _load("install_openbao_current_runtime")
verifier = _load("verify_openbao_release_signature")


def test_openbao_release_is_exactly_pinned():
    assert installer.OPENBAO_VERSION == "2.6.1"
    assert installer.OPENBAO_COMMIT == "ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f"
    assert installer.ARCHIVE_NAME == "openbao_2.6.1_linux_amd64.tar.gz"
    assert installer.CERTIFICATE_IDENTITY == (
        "https://github.com/openbao/openbao/.github/workflows/"
        "release.yml@refs/heads/release/2.6.x"
    )
    assert installer.CERTIFICATE_OIDC_ISSUER == "https://token.actions.githubusercontent.com"
    for digest in (
        installer.ARCHIVE_SHA256,
        installer.BINARY_SHA256,
        installer.CHECKSUMS_SHA256,
        installer.CHECKSUMS_BUNDLE_SHA256,
        installer.ARCHIVE_BUNDLE_SHA256,
    ):
        assert len(digest) == 64
        int(digest, 16)


def test_checksum_manifest_must_bind_exact_archive_once(tmp_path: Path):
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(
        f"{'1' * 64}  another-file\n"
        f"{installer.ARCHIVE_SHA256}  {installer.ARCHIVE_NAME}\n",
        encoding="utf-8",
    )
    installer._validate_checksums(checksums)

    checksums.write_text(
        f"{installer.ARCHIVE_SHA256}  {installer.ARCHIVE_NAME}\n"
        f"{installer.ARCHIVE_SHA256}  {installer.ARCHIVE_NAME}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="does not bind"):
        installer._validate_checksums(checksums)

    checksums.write_text(
        f"{'0' * 64}  {installer.ARCHIVE_NAME}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="does not bind"):
        installer._validate_checksums(checksums)


def test_signature_verification_uses_exact_identity_and_offline_root(monkeypatch, tmp_path: Path):
    captured = {}

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Result()

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    installer._verify_signature(
        blob=tmp_path / "archive",
        bundle=tmp_path / "bundle",
        cosign=tmp_path / "cosign",
        trusted_root=tmp_path / "trusted-root",
    )

    command = captured["command"]
    assert "--trusted-root" in command
    assert "--certificate-identity" in command
    assert installer.CERTIFICATE_IDENTITY in command
    assert "--certificate-identity-regexp" not in command
    assert installer.CERTIFICATE_OIDC_ISSUER in command
    assert captured["kwargs"]["stdout"] is installer.subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] is installer.subprocess.DEVNULL


def test_release_verifier_uses_the_same_exact_signer_boundary():
    assert verifier.CERTIFICATE_IDENTITY == installer.CERTIFICATE_IDENTITY
    assert verifier.CERTIFICATE_OIDC_ISSUER == installer.CERTIFICATE_OIDC_ISSUER
    assert verifier.OPENBAO_ARCHIVE.name == installer.ARCHIVE_NAME
