from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import sys


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "verify_openbao_raft_ha.py"
SPEC = importlib.util.spec_from_file_location("verify_openbao_raft_ha", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


def test_atomic_replace_updates_content_and_private_key_mode(tmp_path: Path):
    source = tmp_path / "replacement-key.pem"
    destination = tmp_path / "server-key.pem"
    source.write_bytes(b"replacement")
    destination.write_bytes(b"original")

    verifier._atomic_replace(source, destination, mode=0o600)

    assert destination.read_bytes() == b"replacement"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".server-key.pem-rotate-*"))


def test_server_config_fixes_tls_files_and_minimum_version(tmp_path: Path):
    config = tmp_path / "server.hcl"
    certificate = tmp_path / "server.pem"
    private_key = tmp_path / "server-key.pem"

    verifier._write_server_config(
        config,
        name="node-1",
        api_port=18200,
        cluster_port=18201,
        data_path=tmp_path / "raft",
        certificate=certificate,
        private_key=private_key,
    )

    rendered = config.read_text(encoding="utf-8")
    assert f'tls_cert_file = "{certificate}"' in rendered
    assert f'tls_key_file = "{private_key}"' in rendered
    assert 'tls_min_version = "tls12"' in rendered
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
