from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "verify_keycloak_oidc_release_signature.py"
)
SPEC = importlib.util.spec_from_file_location(
    "verify_keycloak_oidc_release_signature", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(SCRIPT.parent))
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


def test_mutated_archive_negative_check_changes_one_byte(monkeypatch, tmp_path: Path):
    archive = tmp_path / "release.tar.gz"
    archive.write_bytes(b"0123456789")
    signature = tmp_path / "release.sig"
    signature.write_bytes(b"signature")
    public_key = tmp_path / "release.asc"
    public_key.write_bytes(b"public key")
    observed: list[bytes] = []

    def reject_changed(candidate, *_args):
        observed.append(candidate.read_bytes())
        raise RuntimeError("signature rejected")

    monkeypatch.setattr(verifier, "_verify_detached_signature", reject_changed)

    assert verifier._mutated_archive_is_rejected(
        archive, signature, public_key, "A" * 40
    )
    assert len(observed) == 1
    assert observed[0] != archive.read_bytes()
    assert len(observed[0]) == archive.stat().st_size
