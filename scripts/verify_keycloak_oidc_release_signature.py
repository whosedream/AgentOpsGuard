#!/usr/bin/env python3
"""Reverify the pinned Keycloak and Temurin release signatures offline."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile

from install_keycloak_oidc_runtime import (
    JRE_ARCHIVE_NAME,
    JRE_PUBLIC_KEY_NAME,
    JRE_SIGNATURE_NAME,
    JRE_SIGNER_FINGERPRINT,
    KEYCLOAK_ARCHIVE_NAME,
    KEYCLOAK_PUBLIC_KEY_NAME,
    KEYCLOAK_SIGNATURE_NAME,
    KEYCLOAK_SIGNER_FINGERPRINT,
    KEYCLOAK_VERSION,
    _verify_detached_signature,
    _verify_release_inputs,
)


DEFAULT_RELEASE_DIRECTORY = (
    Path.home() / f".cache/agentops-guard/releases/keycloak/{KEYCLOAK_VERSION}"
)


def _mutated_archive_is_rejected(
    archive: Path,
    signature: Path,
    public_key: Path,
    fingerprint: str,
) -> bool:
    with tempfile.NamedTemporaryFile(
        prefix="agentops-mutated-release-", suffix=".tar.gz", dir="/tmp"
    ) as mutated:
        with archive.open("rb") as source:
            shutil.copyfileobj(source, mutated, length=1024 * 1024)
        mutated.flush()
        position = archive.stat().st_size // 2
        mutated.seek(position)
        original = mutated.read(1)
        if len(original) != 1:
            raise RuntimeError("release archive cannot be mutated for negative verification")
        mutated.seek(position)
        mutated.write(bytes((original[0] ^ 0x01,)))
        mutated.flush()
        try:
            _verify_detached_signature(
                Path(mutated.name), signature, public_key, fingerprint
            )
        except RuntimeError:
            return True
    return False


def verify(release_directory: Path) -> dict[str, object]:
    keycloak_archive = release_directory / KEYCLOAK_ARCHIVE_NAME
    keycloak_signature = release_directory / KEYCLOAK_SIGNATURE_NAME
    keycloak_public_key = release_directory / KEYCLOAK_PUBLIC_KEY_NAME
    jre_archive = release_directory / JRE_ARCHIVE_NAME
    jre_signature = release_directory / JRE_SIGNATURE_NAME
    jre_public_key = release_directory / JRE_PUBLIC_KEY_NAME
    _verify_release_inputs(
        keycloak_archive=keycloak_archive,
        keycloak_signature=keycloak_signature,
        keycloak_public_key=keycloak_public_key,
        jre_archive=jre_archive,
        jre_signature=jre_signature,
        jre_public_key=jre_public_key,
    )
    mutated_keycloak_archive_rejected = _mutated_archive_is_rejected(
        keycloak_archive,
        keycloak_signature,
        keycloak_public_key,
        KEYCLOAK_SIGNER_FINGERPRINT,
    )
    mutated_jre_archive_rejected = _mutated_archive_is_rejected(
        jre_archive,
        jre_signature,
        jre_public_key,
        JRE_SIGNER_FINGERPRINT,
    )
    if not mutated_keycloak_archive_rejected or not mutated_jre_archive_rejected:
        raise RuntimeError("a changed identity-runtime archive passed signature verification")
    return {
        "schema_version": "agentops.keycloak-oidc-release-provenance.v1",
        "keycloak_version": KEYCLOAK_VERSION,
        "keycloak_signature_verified": True,
        "keycloak_signer_fingerprint_exact_match": True,
        "temurin_signature_verified": True,
        "temurin_signer_fingerprint_exact_match": True,
        "mutated_keycloak_archive_rejected": True,
        "mutated_temurin_archive_rejected": True,
        "network_required": False,
        "archive_content_in_report": False,
        "gpg_output_in_report": False,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-directory", type=Path, default=DEFAULT_RELEASE_DIRECTORY
    )
    args = parser.parse_args()
    print(json.dumps(verify(args.release_directory), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
