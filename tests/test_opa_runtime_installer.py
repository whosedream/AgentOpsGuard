from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install_opa_current_runtime.py"
SPEC = importlib.util.spec_from_file_location("install_opa_current_runtime", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


def test_checksum_file_is_bound_to_reviewed_digest_and_asset_name(tmp_path: Path):
    checksum = tmp_path / "opa.sha256"
    checksum.write_text(
        f"{installer.OPA_BINARY_SHA256}  {installer.OPA_ASSET_NAME}\n",
        encoding="utf-8",
    )

    installer._validate_checksum_file(checksum)


@pytest.mark.parametrize(
    "line",
    (
        f"{'0' * 64}  opa_linux_amd64_static\n",
        f"{installer.OPA_BINARY_SHA256}  different-asset\n",
        f"{installer.OPA_BINARY_SHA256}\n",
    ),
)
def test_checksum_file_rejects_unreviewed_content(tmp_path: Path, line: str):
    checksum = tmp_path / "opa.sha256"
    checksum.write_text(line, encoding="utf-8")

    with pytest.raises(RuntimeError, match="checksum file"):
        installer._validate_checksum_file(checksum)
