from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import sys

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "verify_postgres_streaming_failover.py"
)
SPEC = importlib.util.spec_from_file_location("verify_postgres_streaming_failover", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


def test_postgres_failover_image_is_immutable():
    assert verifier.POSTGRES_IMAGE == (
        "postgres@sha256:"
        "95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b"
    )


def test_private_runtime_file_is_exclusive_and_owner_only(tmp_path: Path):
    path = tmp_path / "runtime.env"
    verifier._write_private_text(path, "generated-at-runtime")

    assert path.read_text(encoding="utf-8") == "generated-at-runtime"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        verifier._write_private_text(path, "replacement")


def test_child_environment_does_not_inherit_ambient_credentials(monkeypatch):
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-be-inherited")

    environment = verifier._child_environment("postgresql://trusted-runtime-reference")

    assert "UNRELATED_SECRET" not in environment
    assert environment["AGENTOPS_DATABASE_URL"] == "postgresql://trusted-runtime-reference"
    assert environment["AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP"] == "false"
