"""Narrow compatibility rule for historical evaluations after reviewed security patches."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evals" / "bipia-runtime-compatible-locks.json"
MANIFEST_SHA256 = "7a1176db8ba54113b0944b460795042f491066fbcbea098f390c5a82778de5c9"
EXPECTED_CHANGES = [
    {"package": "pydantic-settings", "from": "2.14.0", "to": "2.14.2"},
    {"package": "starlette", "from": "1.0.0", "to": "1.3.1"},
]


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def assert_compatible_uv_lock(*, baseline: str, current: str) -> None:
    if _sha256(MANIFEST) != MANIFEST_SHA256:
        raise RuntimeError("evaluation lock compatibility manifest changed")
    compatibility = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if compatibility != {
        "schema_version": 1,
        "evidence": "artifacts/benchmarks/bipia_static_holdout_v1.json",
        "baseline_uv_lock_sha256": baseline,
        "compatible_uv_lock_sha256": current,
        "reconstructed_baseline_sha256": baseline,
        "reason": "security_patch_only_no_scanner_or_model_dependency_change",
        "changes": EXPECTED_CHANGES,
    }:
        raise RuntimeError("evaluation lock compatibility contract changed")

    with (ROOT / "uv.lock").open("rb") as handle:
        packages = {
            package["name"]: package["version"]
            for package in tomllib.load(handle).get("package", [])
        }
    for change in EXPECTED_CHANGES:
        if packages.get(change["package"]) != change["to"]:
            raise RuntimeError("compatible evaluation dependency version changed")
