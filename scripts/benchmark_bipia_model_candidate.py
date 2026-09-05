#!/usr/bin/env python3
"""Compare one source-pinned shadow-model candidate on the now-known BIPIA corpus."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from agentops_guard.benchmarks.bipia import (
    DEFAULT_REPOSITORY,
    load_bipia_samples,
    load_source_lock,
    summarize_bipia_results,
)
from agentops_guard.benchmarks.llmail_inject import evaluate_samples, file_sha256


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_LOCK = ROOT / "evals" / "protectai-deberta-v3-base-prompt-injection-v2.json"
DEFAULT_MODEL_PATH = (
    Path.home()
    / ".cache"
    / "agentops-guard-models"
    / "protectai-deberta-v3-base-prompt-injection-v2-runtime"
)
DEFAULT_OUTPUT = (
    ROOT / "artifacts" / "benchmarks" / "bipia_protectai_candidate_regression_v1.json"
)
BASELINE_REPORT = ROOT / "artifacts" / "benchmarks" / "bipia_static_holdout_v1.json"
BASELINE_REPORT_SHA256 = (
    "4e9bb897996d85cad3e7bc15859abecd6b361a448d1e30a22e9a1063f74e53e6"
)


def _load_candidate_lock() -> dict[str, Any]:
    lock = json.loads(CANDIDATE_LOCK.read_text(encoding="utf-8"))
    if (
        lock.get("source")
        != "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2"
        or lock.get("revision") != "90c9989b1a342275dd0d1a95aad283c04e075671"
        or lock.get("license") != "Apache-2.0"
        or lock.get("risk_label") != "INJECTION"
        or not isinstance(lock.get("files"), dict)
    ):
        raise RuntimeError("candidate model lock changed")
    return lock


def _validate_candidate(model_path: Path, lock: dict[str, Any]) -> None:
    if file_sha256(BASELINE_REPORT) != BASELINE_REPORT_SHA256:
        raise RuntimeError("BIPIA first-run baseline changed")
    for name, expected in lock["files"].items():
        path = model_path / name
        if not path.is_file() or file_sha256(path) != expected:
            raise RuntimeError(f"candidate model asset mismatch: {name}")
    if file_sha256(model_path / "manifest.json") != lock["runtime_manifest_sha256"]:
        raise RuntimeError("candidate runtime manifest changed")


def _implementation_hashes() -> dict[str, str]:
    paths = (
        "evals/bipia-source.json",
        "evals/protectai-deberta-v3-base-prompt-injection-v2.json",
        "pyproject.toml",
        "scripts/benchmark_bipia_model_candidate.py",
        "src/agentops_guard/backend/schemas.py",
        "src/agentops_guard/backend/services/content.py",
        "src/agentops_guard/backend/services/policy.py",
        "src/agentops_guard/backend/services/scanner.py",
        "src/agentops_guard/backend/services/semantic_scanner.py",
        "src/agentops_guard/benchmarks/bipia.py",
        "src/agentops_guard/benchmarks/llmail_inject.py",
        "uv.lock",
    )
    return {path: file_sha256(ROOT / path) for path in paths}


def _write_new_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the fixed ProtectAI BIPIA candidate")
    parser.add_argument("--bipia-repository", type=Path, default=DEFAULT_REPOSITORY)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--threshold", type=float, default=0.90)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if not 0 < args.threshold < 1:
        parser.error("--threshold must be between 0 and 1")
    if args.output.exists():
        parser.error("output already exists; candidate evidence is immutable")

    candidate_lock = _load_candidate_lock()
    model_path = args.model_path.resolve()
    _validate_candidate(model_path, candidate_lock)
    samples, inventory = load_bipia_samples(args.bipia_repository)
    if (
        inventory.get("attack_rows") != 13_750
        or inventory.get("benign_rows") != 200
        or len(samples) != 13_950
    ):
        raise RuntimeError("BIPIA candidate corpus changed")
    results = evaluate_samples(
        samples,
        model_path=model_path,
        model_sha256=candidate_lock["files"]["model.safetensors"],
        manifest_sha256=candidate_lock["runtime_manifest_sha256"],
        threshold=args.threshold,
        workers=args.workers,
    )
    source_lock = load_source_lock()
    report = {
        "metadata": {
            "created_at": datetime.now(UTC).isoformat(),
            "git_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "git_dirty": bool(
                subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=ROOT, text=True
                ).strip()
            ),
            "runtime": {
                "python": sys.version,
                "platform": platform.platform(),
                "workers": args.workers,
            },
            "dataset": {
                "name": "Microsoft BIPIA",
                "source": source_lock["repository"],
                "commit": source_lock["commit"],
                **inventory,
            },
            "model": {
                "id": "protectai/deberta-v3-base-prompt-injection-v2",
                "source": candidate_lock["source"],
                "revision": candidate_lock["revision"],
                "license": candidate_lock["license"],
                "risk_label": candidate_lock["risk_label"],
                "sha256": candidate_lock["files"]["model.safetensors"],
                "manifest_sha256": candidate_lock["runtime_manifest_sha256"],
                "threshold": args.threshold,
                "mode": "candidate_shadow_only",
            },
            "implementation_sha256": _implementation_hashes(),
            "evidence_kind": "post_holdout_candidate_comparison",
            "baseline": {
                "report": "artifacts/benchmarks/bipia_static_holdout_v1.json",
                "sha256": BASELINE_REPORT_SHA256,
            },
            "scope": (
                "Post-holdout drop-in comparison using the same sanitization, 512-character "
                "sampling, rules, 0.90 threshold, and BIPIA corpus as the frozen first run. The "
                "corpus is now known, so this is not blind evidence and cannot by itself promote "
                "the candidate."
            ),
            "privacy": {
                "stores_raw_cases": False,
                "stores_per_case_results": False,
                "stores_model_scores": False,
            },
        },
        "summary": summarize_bipia_results(results),
    }
    _write_new_report(report, args.output)
    attack = report["summary"]["attack"]
    benign = report["summary"]["benign"]
    print(
        f"attack_combined={attack['combined_flagged']}/{attack['rows']} "
        f"benign_combined={benign['combined_flagged']}/{benign['rows']} "
        "report_created=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
