from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install_keycloak_oidc_runtime.py"
SPEC = importlib.util.spec_from_file_location("install_keycloak_oidc_runtime", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


def _archive_tree(source: Path, archive: Path, root_name: str) -> None:
    with tarfile.open(archive, "w:gz") as target:
        target.add(source, arcname=root_name)


def _fake_archives(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    keycloak_tree = tmp_path / "keycloak-tree"
    keycloak_bin = keycloak_tree / "bin"
    keycloak_bin.mkdir(parents=True)
    keycloak_script = keycloak_bin / "kc.sh"
    keycloak_script.write_text(
        f"#!/bin/sh\necho 'Keycloak {installer.KEYCLOAK_VERSION}'\n",
        encoding="utf-8",
    )
    keycloak_script.chmod(0o500)
    jre_tree = tmp_path / "jre-tree"
    jre_bin = jre_tree / "bin"
    jre_bin.mkdir(parents=True)
    java = jre_bin / "java"
    java.write_text(
        f"#!/bin/sh\necho 'openjdk version \"{installer.JRE_RUNTIME_VERSION}\"' >&2\n",
        encoding="utf-8",
    )
    java.chmod(0o500)
    keycloak_archive = tmp_path / installer.KEYCLOAK_ARCHIVE_NAME
    jre_archive = tmp_path / installer.JRE_ARCHIVE_NAME
    _archive_tree(keycloak_tree, keycloak_archive, installer.KEYCLOAK_ARCHIVE_ROOT)
    _archive_tree(jre_tree, jre_archive, installer.JRE_ARCHIVE_ROOT)
    keycloak_signature = tmp_path / installer.KEYCLOAK_SIGNATURE_NAME
    keycloak_signature.write_bytes(b"keycloak detached signature fixture")
    keycloak_public_key = tmp_path / installer.KEYCLOAK_PUBLIC_KEY_NAME
    keycloak_public_key.write_bytes(b"keycloak public key fixture")
    jre_signature = tmp_path / installer.JRE_SIGNATURE_NAME
    jre_signature.write_bytes(b"jre detached signature fixture")
    jre_public_key = tmp_path / installer.JRE_PUBLIC_KEY_NAME
    jre_public_key.write_bytes(b"jre public key fixture")
    return (
        keycloak_archive,
        keycloak_signature,
        keycloak_public_key,
        jre_archive,
        jre_signature,
        jre_public_key,
    )


def test_installs_verified_archives_without_overwrite(monkeypatch, tmp_path: Path):
    inputs = _fake_archives(tmp_path)
    (
        keycloak_archive,
        keycloak_signature,
        keycloak_public_key,
        jre_archive,
        jre_signature,
        jre_public_key,
    ) = inputs
    digest_attributes = (
        ("KEYCLOAK_ARCHIVE_SHA256", keycloak_archive),
        ("KEYCLOAK_SIGNATURE_SHA256", keycloak_signature),
        ("KEYCLOAK_PUBLIC_KEY_SHA256", keycloak_public_key),
        ("JRE_ARCHIVE_SHA256", jre_archive),
        ("JRE_SIGNATURE_SHA256", jre_signature),
        ("JRE_PUBLIC_KEY_SHA256", jre_public_key),
    )
    for attribute, path in digest_attributes:
        monkeypatch.setattr(
            installer,
            attribute,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    signature_checks: list[tuple[Path, Path, Path, str]] = []
    monkeypatch.setattr(
        installer,
        "_verify_detached_signature",
        lambda archive, signature, public_key, fingerprint: signature_checks.append(
            (archive, signature, public_key, fingerprint)
        ),
    )
    destination = tmp_path / "runtime"

    installer.install_runtime(*inputs, destination)

    assert (destination / "keycloak/bin/kc.sh").is_file()
    assert (destination / "jre/bin/java").is_file()
    assert (destination / "release.json").stat().st_mode & 0o777 == 0o400
    assert signature_checks == [
        (
            keycloak_archive,
            keycloak_signature,
            keycloak_public_key,
            installer.KEYCLOAK_SIGNER_FINGERPRINT,
        ),
        (
            jre_archive,
            jre_signature,
            jre_public_key,
            installer.JRE_SIGNER_FINGERPRINT,
        ),
    ]
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        installer.install_runtime(*inputs, destination)


@pytest.mark.parametrize("member_name", ("../escape", "/absolute", "root/../../escape"))
def test_rejects_archive_paths_outside_reviewed_root(tmp_path: Path, member_name: str):
    archive = tmp_path / "malicious.tar.gz"
    payload = b"escape"
    with tarfile.open(archive, "w:gz") as target:
        member = tarfile.TarInfo(member_name)
        member.size = len(payload)
        target.addfile(member, io.BytesIO(payload))

    with pytest.raises(RuntimeError, match="archive path|top-level"):
        installer._extract_archive(
            archive,
            tmp_path / "extract",
            expected_root="root",
            max_unpacked_bytes=1024,
        )


def test_rejects_symlink_that_escapes_reviewed_root(tmp_path: Path):
    archive = tmp_path / "malicious-link.tar.gz"
    with tarfile.open(archive, "w:gz") as target:
        root = tarfile.TarInfo("root")
        root.type = tarfile.DIRTYPE
        target.addfile(root)
        link = tarfile.TarInfo("root/outside")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../escape"
        target.addfile(link)

    with pytest.raises(RuntimeError, match="link escapes"):
        installer._extract_archive(
            archive,
            tmp_path / "extract",
            expected_root="root",
            max_unpacked_bytes=1024,
        )
