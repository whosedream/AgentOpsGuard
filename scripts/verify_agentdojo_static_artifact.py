#!/usr/bin/env python3
"""Verify immutable AgentDojo static first-run and current regression evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_REPORT = ROOT / "artifacts" / "benchmarks" / "agentdojo_static_blind_v1.json"
HISTORICAL_REPORT_SHA256 = (
    "84fc70e9df645e6f26b33957b57acc518ea0756361fa49e45b512dd2efc1583b"
)
PREVIOUS_REPORT = ROOT / "artifacts" / "benchmarks" / "agentdojo_static_regression_v2.json"
PREVIOUS_REPORT_SHA256 = "1afe3eefc629c48a3b75de57207bf86a783c5019c23dc966bd2c34731248f4fb"
CURRENT_REPORT = ROOT / "artifacts" / "benchmarks" / "agentdojo_static_regression_v3.json"
CURRENT_REPORT_SHA256 = "f40f7e552e33a110d953f447ee9c930dc1c6c6e3e06db82fed05b989258118d8"
EVAL_PYTHON = ROOT / "evals" / "inspect" / ".venv" / "bin" / "python"
EXPORTER = ROOT / "evals" / "inspect" / "export_agentdojo_static_cases.py"
CORPUS_SHA256 = "b9e626a936311cd2cf0ec250aeea8f0f1e885a64beb2bd1ec1829359ba744c73"
MODEL_SHA256 = "0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0"


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _safe_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _assert_dataset_and_results(report: dict) -> None:
    metadata = report["metadata"]
    dataset = metadata["dataset"]
    if (
        dataset["package_version"] != "0.1.35"
        or dataset["benchmark_version"] != "v1.2.2"
        or dataset["selected_attack_rows"] != 140
        or dataset["selected_benign_rows"] != 97
        or dataset["selected_corpus_sha256"] != CORPUS_SHA256
    ):
        raise RuntimeError("AgentDojo static dataset evidence changed")
    attack = report["summary"]["attack"]
    benign = report["summary"]["benign"]
    if (
        attack["rows"] != 140
        or attack["regex_flagged"] != 38
        or attack["model_flagged"] != 105
        or attack["combined_flagged"] != 107
        or benign["rows"] != 97
        or benign["regex_flagged"] != 0
        or benign["model_flagged"] != 9
        or benign["combined_flagged"] != 9
    ):
        raise RuntimeError("AgentDojo static aggregate result changed")
    if metadata["model"]["sha256"] != MODEL_SHA256:
        raise RuntimeError("AgentDojo static model evidence changed")


def main() -> int:
    if _sha256(HISTORICAL_REPORT) != HISTORICAL_REPORT_SHA256:
        raise RuntimeError("AgentDojo static first-run report SHA-256 changed")
    historical = json.loads(HISTORICAL_REPORT.read_text(encoding="utf-8"))
    _assert_dataset_and_results(historical)

    if _sha256(PREVIOUS_REPORT) != PREVIOUS_REPORT_SHA256:
        raise RuntimeError("AgentDojo static previous report SHA-256 changed")
    previous = json.loads(PREVIOUS_REPORT.read_text(encoding="utf-8"))
    _assert_dataset_and_results(previous)

    if _sha256(CURRENT_REPORT) != CURRENT_REPORT_SHA256:
        raise RuntimeError("AgentDojo static current report SHA-256 changed")
    current = json.loads(CURRENT_REPORT.read_text(encoding="utf-8"))
    _assert_dataset_and_results(current)
    metadata = current["metadata"]
    if metadata.get("evidence_kind") != "post_first_run_regression" or metadata.get(
        "historical_first_run"
    ) != {
        "report": "artifacts/benchmarks/agentdojo_static_blind_v1.json",
        "sha256": HISTORICAL_REPORT_SHA256,
    }:
        raise RuntimeError("AgentDojo static evidence lineage changed")
    for relative_path, expected in metadata["implementation_sha256"].items():
        if _sha256(ROOT / relative_path) != expected:
            raise RuntimeError(f"AgentDojo current implementation changed: {relative_path}")

    if _sha256(ROOT / "models" / "semantic-guard" / "model.safetensors") != MODEL_SHA256:
        raise RuntimeError("local semantic model no longer matches AgentDojo evidence")

    completed = subprocess.run(
        [str(EVAL_PYTHON), str(EXPORTER)],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0 or hashlib.sha256(completed.stdout.strip()).hexdigest() != CORPUS_SHA256:
        raise RuntimeError("current AgentDojo corpus does not match static evidence")
    print("agentdojo_static_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
