#!/usr/bin/env python3
"""Install a pinned Keycloak and Java runtime outside the repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import subprocess
import tarfile
import tempfile


KEYCLOAK_VERSION = "26.7.3"
KEYCLOAK_ARCHIVE_NAME = f"keycloak-{KEYCLOAK_VERSION}.tar.gz"
KEYCLOAK_ARCHIVE_SHA256 = "77657f30b7e90d70f727712ce1c967f430fd6a5e9f458d32d8c6df0635345f47"
KEYCLOAK_ARCHIVE_ROOT = f"keycloak-{KEYCLOAK_VERSION}"
KEYCLOAK_SIGNATURE_NAME = f"{KEYCLOAK_ARCHIVE_NAME}.asc"
KEYCLOAK_SIGNATURE_SHA256 = "128903d42c4b10e189cc922a89b3671ab60b8dbcd4f6b90091bc21751e54b7e6"
KEYCLOAK_PUBLIC_KEY_NAME = "keycloak-2.asc"
KEYCLOAK_PUBLIC_KEY_SHA256 = "cc0aafd52039fa77266f451bebfcb67cdfc2391e7204a160872cd9ab3163970a"
KEYCLOAK_SIGNER_FINGERPRINT = "861AB50E8CC6611FB6BC01A6B8F12EA26FD6EEBA"
JRE_VERSION = "21.0.12.1+1"
JRE_RUNTIME_VERSION = "21.0.12"
JRE_ARCHIVE_NAME = "OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz"
JRE_ARCHIVE_SHA256 = "2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500"
JRE_ARCHIVE_ROOT = "jdk-21.0.12.1+1-jre"
JRE_SIGNATURE_NAME = f"{JRE_ARCHIVE_NAME}.sig"
JRE_SIGNATURE_SHA256 = "269a886dc5f1fc39bf640cc0a1a39473932a3f40f49492dcb81b0d09bc5822d6"
JRE_PUBLIC_KEY_NAME = "adoptium-public.asc"
JRE_PUBLIC_KEY_SHA256 = "a46d5d3ab75c3c86dddf1bfd2957a067a24b1c6b2d2ed2bc69294bf970c5160b"
JRE_SIGNER_FINGERPRINT = "3B04D753C9050D9A5D343F39843C48A565F8F04B"
DEFAULT_DESTINATION = (
    Path.home() / f".local/share/agentops-guard/keycloak/{KEYCLOAK_VERSION}-signed-v1"
)
MAX_ARCHIVE_MEMBERS = 100_000
MAX_KEYCLOAK_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_JRE_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalised_member_path(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise RuntimeError("runtime archive contains an invalid path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise RuntimeError("runtime archive path escapes its reviewed root")
    return path


def _gpg_environment(home: Path) -> dict[str, str]:
    return {
        "GNUPGHOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
    }


def _primary_public_key_fingerprint(public_key: Path, home: Path) -> str:
    result = subprocess.run(
        (
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            str(public_key),
        ),
        env=_gpg_environment(home),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("release public key cannot be parsed")
    primary_fingerprints: list[str] = []
    awaiting_primary_fingerprint = False
    public_key_count = 0
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            public_key_count += 1
            awaiting_primary_fingerprint = True
        elif fields[0] == "fpr" and awaiting_primary_fingerprint:
            primary_fingerprints.append(fields[9])
            awaiting_primary_fingerprint = False
    if public_key_count != 1 or len(primary_fingerprints) != 1:
        raise RuntimeError("release public key file must contain exactly one primary key")
    return primary_fingerprints[0]


def _verify_detached_signature(
    archive: Path,
    signature: Path,
    public_key: Path,
    expected_fingerprint: str,
) -> None:
    if not 0 < signature.stat().st_size <= MAX_SIGNATURE_BYTES:
        raise RuntimeError("release signature has an unexpected size")
    if not 0 < public_key.stat().st_size <= MAX_PUBLIC_KEY_BYTES:
        raise RuntimeError("release public key has an unexpected size")
    with tempfile.TemporaryDirectory(prefix="agentops-release-gpg-", dir="/tmp") as temp:
        home = Path(temp)
        home.chmod(0o700)
        if _primary_public_key_fingerprint(public_key, home) != expected_fingerprint:
            raise RuntimeError("release public key fingerprint does not match the reviewed signer")
        imported = subprocess.run(
            ("gpg", "--batch", "--homedir", str(home), "--import", str(public_key)),
            env=_gpg_environment(home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        if imported.returncode != 0:
            raise RuntimeError("release public key import failed")
        verified = subprocess.run(
            (
                "gpg",
                "--batch",
                "--homedir",
                str(home),
                "--status-fd=1",
                "--verify",
                str(signature),
                str(archive),
            ),
            env=_gpg_environment(home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            text=True,
        )
        valid_signers = {
            line.split()[2]
            for line in verified.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
        }
        if verified.returncode != 0 or valid_signers != {expected_fingerprint}:
            raise RuntimeError("release signature or signer identity did not verify")


def _verify_release_inputs(
    *,
    keycloak_archive: Path,
    keycloak_signature: Path,
    keycloak_public_key: Path,
    jre_archive: Path,
    jre_signature: Path,
    jre_public_key: Path,
) -> None:
    inputs = (
        (keycloak_archive, KEYCLOAK_ARCHIVE_SHA256, KEYCLOAK_ARCHIVE_NAME),
        (keycloak_signature, KEYCLOAK_SIGNATURE_SHA256, KEYCLOAK_SIGNATURE_NAME),
        (keycloak_public_key, KEYCLOAK_PUBLIC_KEY_SHA256, KEYCLOAK_PUBLIC_KEY_NAME),
        (jre_archive, JRE_ARCHIVE_SHA256, JRE_ARCHIVE_NAME),
        (jre_signature, JRE_SIGNATURE_SHA256, JRE_SIGNATURE_NAME),
        (jre_public_key, JRE_PUBLIC_KEY_SHA256, JRE_PUBLIC_KEY_NAME),
    )
    for path, expected_digest, expected_name in inputs:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"reviewed runtime input is missing: {expected_name}")
        if _sha256_file(path) != expected_digest:
            raise RuntimeError(f"runtime digest does not match reviewed asset: {expected_name}")
    _verify_detached_signature(
        keycloak_archive,
        keycloak_signature,
        keycloak_public_key,
        KEYCLOAK_SIGNER_FINGERPRINT,
    )
    _verify_detached_signature(
        jre_archive,
        jre_signature,
        jre_public_key,
        JRE_SIGNER_FINGERPRINT,
    )


def _validate_link(member: tarfile.TarInfo, expected_root: str) -> None:
    link_name = member.linkname
    if not link_name or "\\" in link_name or "\x00" in link_name:
        raise RuntimeError("runtime archive contains an invalid link")
    link_path = PurePosixPath(link_name)
    if link_path.is_absolute():
        raise RuntimeError("runtime archive contains an absolute link")
    if member.issym():
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(member.name), link_name)
        )
    else:
        resolved = posixpath.normpath(link_name)
    resolved_path = PurePosixPath(resolved)
    if (
        resolved_path.is_absolute()
        or ".." in resolved_path.parts
        or not resolved_path.parts
        or resolved_path.parts[0] != expected_root
    ):
        raise RuntimeError("runtime archive link escapes its reviewed root")


def _validated_members(
    source: tarfile.TarFile,
    *,
    expected_root: str,
    max_unpacked_bytes: int,
) -> list[tarfile.TarInfo]:
    members = source.getmembers()
    if not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise RuntimeError("runtime archive has an unexpected member count")
    total_bytes = 0
    for member in members:
        path = _normalised_member_path(member.name)
        if path.parts[0] != expected_root:
            raise RuntimeError("runtime archive contains an unexpected top-level path")
        if member.mode & 0o6000:
            raise RuntimeError("runtime archive contains elevated permission bits")
        if member.isfile():
            if member.size < 0:
                raise RuntimeError("runtime archive contains a negative file size")
            total_bytes += member.size
            if total_bytes > max_unpacked_bytes:
                raise RuntimeError("runtime archive exceeds the unpacked size limit")
        elif member.issym() or member.islnk():
            _validate_link(member, expected_root)
        elif not member.isdir():
            raise RuntimeError("runtime archive contains a special file")
    return members


def _extract_archive(
    archive: Path,
    destination: Path,
    *,
    expected_root: str,
    max_unpacked_bytes: int,
) -> Path:
    with tarfile.open(archive, "r:gz") as source:
        members = _validated_members(
            source,
            expected_root=expected_root,
            max_unpacked_bytes=max_unpacked_bytes,
        )
        source.extractall(destination, members=members, filter="data")
    extracted_root = destination / expected_root
    if not extracted_root.is_dir() or extracted_root.is_symlink():
        raise RuntimeError("runtime archive did not produce the reviewed root directory")
    if {path.name for path in destination.iterdir()} != {expected_root}:
        raise RuntimeError("runtime archive produced an unexpected top-level path")
    return extracted_root


def _runtime_environment(java_home: Path) -> dict[str, str]:
    return {
        "JAVA_HOME": str(java_home),
        "PATH": f"{java_home / 'bin'}:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "LANG": "C",
    }


def _verify_versions(destination: Path) -> None:
    java_home = destination / "jre"
    java = java_home / "bin" / "java"
    keycloak = destination / "keycloak" / "bin" / "kc.sh"
    if not java.is_file() or java.is_symlink() or not keycloak.is_file():
        raise RuntimeError("installed OIDC runtime is incomplete")
    environment = _runtime_environment(java_home)
    java_result = subprocess.run(
        (str(java), "-version"),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if java_result.returncode != 0 or JRE_RUNTIME_VERSION.encode() not in (
        java_result.stdout + java_result.stderr
    ):
        raise RuntimeError("installed Java runtime reported an unexpected version")
    keycloak_result = subprocess.run(
        (str(keycloak), "--version"),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if keycloak_result.returncode != 0 or KEYCLOAK_VERSION.encode() not in (
        keycloak_result.stdout + keycloak_result.stderr
    ):
        raise RuntimeError("installed Keycloak runtime reported an unexpected version")


def install_runtime(
    keycloak_archive: Path,
    keycloak_signature: Path,
    keycloak_public_key: Path,
    jre_archive: Path,
    jre_signature: Path,
    jre_public_key: Path,
    destination: Path,
) -> None:
    _verify_release_inputs(
        keycloak_archive=keycloak_archive,
        keycloak_signature=keycloak_signature,
        keycloak_public_key=keycloak_public_key,
        jre_archive=jre_archive,
        jre_signature=jre_signature,
        jre_public_key=jre_public_key,
    )
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("OIDC runtime destination already exists; refusing to overwrite it")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=".keycloak-install-", dir=destination.parent))
    try:
        keycloak_extract = staging / "keycloak-extract"
        jre_extract = staging / "jre-extract"
        keycloak_extract.mkdir(mode=0o700)
        jre_extract.mkdir(mode=0o700)
        keycloak_root = _extract_archive(
            keycloak_archive,
            keycloak_extract,
            expected_root=KEYCLOAK_ARCHIVE_ROOT,
            max_unpacked_bytes=MAX_KEYCLOAK_UNPACKED_BYTES,
        )
        jre_root = _extract_archive(
            jre_archive,
            jre_extract,
            expected_root=JRE_ARCHIVE_ROOT,
            max_unpacked_bytes=MAX_JRE_UNPACKED_BYTES,
        )
        keycloak_root.rename(staging / "keycloak")
        jre_root.rename(staging / "jre")
        keycloak_extract.rmdir()
        jre_extract.rmdir()
        (staging / "release.json").write_text(
            json.dumps(
                {
                    "keycloak_version": KEYCLOAK_VERSION,
                    "keycloak_archive_sha256": KEYCLOAK_ARCHIVE_SHA256,
                    "keycloak_signature_sha256": KEYCLOAK_SIGNATURE_SHA256,
                    "keycloak_public_key_sha256": KEYCLOAK_PUBLIC_KEY_SHA256,
                    "keycloak_signer_fingerprint": KEYCLOAK_SIGNER_FINGERPRINT,
                    "jre_version": JRE_VERSION,
                    "jre_archive_sha256": JRE_ARCHIVE_SHA256,
                    "jre_signature_sha256": JRE_SIGNATURE_SHA256,
                    "jre_public_key_sha256": JRE_PUBLIC_KEY_SHA256,
                    "jre_signer_fingerprint": JRE_SIGNER_FINGERPRINT,
                    "detached_signatures_verified": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        (staging / "release.json").chmod(0o400)
        _verify_versions(staging)
        os.rename(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keycloak-archive", required=True, type=Path)
    parser.add_argument("--keycloak-signature", required=True, type=Path)
    parser.add_argument("--keycloak-public-key", required=True, type=Path)
    parser.add_argument("--jre-archive", required=True, type=Path)
    parser.add_argument("--jre-signature", required=True, type=Path)
    parser.add_argument("--jre-public-key", required=True, type=Path)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    install_runtime(
        args.keycloak_archive,
        args.keycloak_signature,
        args.keycloak_public_key,
        args.jre_archive,
        args.jre_signature,
        args.jre_public_key,
        args.destination,
    )
    print(
        json.dumps(
            {
                "installed": True,
                "keycloak_version": KEYCLOAK_VERSION,
                "keycloak_archive_sha256": KEYCLOAK_ARCHIVE_SHA256,
                "keycloak_signature_sha256": KEYCLOAK_SIGNATURE_SHA256,
                "keycloak_signer_fingerprint": KEYCLOAK_SIGNER_FINGERPRINT,
                "jre_version": JRE_VERSION,
                "jre_archive_sha256": JRE_ARCHIVE_SHA256,
                "jre_signature_sha256": JRE_SIGNATURE_SHA256,
                "jre_signer_fingerprint": JRE_SIGNER_FINGERPRINT,
                "detached_signatures_verified": True,
                "destination_preexisted": False,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
