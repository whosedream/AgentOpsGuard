#!/usr/bin/env python3
"""Run one frozen static holdout scan over the official Microsoft BIPIA test data."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from agentops_guard.backend.services.semantic_scanner import (
    SEMANTIC_MANIFEST_SHA256,
    SEMANTIC_MODEL_ID,
)
from agentops_guard.benchmarks.bipia import (
    DEFAULT_REPOSITORY,
    load_bipia_samples,
    load_source_lock,
    summarize_bipia_results,
)
from agentops_guard.benchmarks.llmail_inject import (
    DEFAULT_MODEL_PATH,
    DEFAULT_MODEL_SHA256,
    evaluate_samples,
    file_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks" / "bipia_static_holdout_v1.json"
EXPECTED_ATTACK_ROWS = 13_750
EXPECTED_BENIGN_ROWS = 200
EXPECTED_ATTACK_ROWS_BY_TASK = {"code": 2_500, "email": 3_750, "table": 7_500}
EXPECTED_BENIGN_ROWS_BY_TASK = {"code": 50, "email": 50, "table": 100}


def _implementation_hashes() -> dict[str, str]:
    paths = (
        "evals/bipia-source.json",
        "pyproject.toml",
        "scripts/benchmark_bipia_static.py",
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


def _validate_inventory(inventory: dict[str, Any]) -> None:
    expected = {
        "attack_rows": EXPECTED_ATTACK_ROWS,
        "benign_rows": EXPECTED_BENIGN_ROWS,
        "attack_rows_by_task": EXPECTED_ATTACK_ROWS_BY_TASK,
        "benign_rows_by_task": EXPECTED_BENIGN_ROWS_BY_TASK,
        "text_attack_families": 15,
        "text_attack_variants": 75,
        "code_attack_families": 10,
        "code_attack_variants": 50,
        "insertion_position": "end",
    }
    for key, value in expected.items():
        if inventory.get(key) != value:
            raise RuntimeError(f"BIPIA selected inventory changed: {key}")


def _write_new_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the frozen BIPIA static external-content holdout"
    )
    parser.add_argument("--bipia-repository", type=Path, default=DEFAULT_REPOSITORY)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--model-sha256", default=DEFAULT_MODEL_SHA256)
    parser.add_argument("--manifest-sha256", default=SEMANTIC_MANIFEST_SHA256)
    parser.add_argument("--threshold", type=float, default=0.90)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if not 0 < args.threshold < 1:
        parser.error("--threshold must be between 0 and 1")
    if args.output.exists():
        parser.error("output already exists; holdout evidence is immutable")

    samples, inventory = load_bipia_samples(args.bipia_repository)
    _validate_inventory(inventory)
    if len(samples) != EXPECTED_ATTACK_ROWS + EXPECTED_BENIGN_ROWS:
        raise RuntimeError("BIPIA selected sample count changed")

    results = evaluate_samples(
        samples,
        model_path=args.model_path.resolve(),
        model_sha256=args.model_sha256,
        manifest_sha256=args.manifest_sha256,
        threshold=args.threshold,
        workers=args.workers,
    )
    lock = load_source_lock()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    report = {
        "metadata": {
            "created_at": datetime.now(UTC).isoformat(),
            "git_commit": commit,
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
                "source": lock["repository"],
                "commit": lock["commit"],
                "package_version": lock["package_version"],
                "repository_code_license": "MIT",
                "data_provenance": {
                    "email": "OpenAI Evals-derived data distributed by BIPIA",
                    "table": "WikiTableQuestions-derived data distributed by BIPIA",
                    "code": "Stack Exchange-derived data distributed by BIPIA",
                    "notice": "Use remains subject to applicable upstream data terms.",
                },
                "source_blobs": {
                    path: specification["sha256"]
                    for path, specification in sorted(lock["files"].items())
                },
                **inventory,
            },
            "model": {
                "id": SEMANTIC_MODEL_ID,
                "sha256": args.model_sha256,
                "manifest_sha256": args.manifest_sha256,
                "threshold": args.threshold,
                "mode": "shadow",
            },
            "implementation_sha256": _implementation_hashes(),
            "evidence_kind": "first_run_pre_tuning_external_holdout",
            "scope": (
                "First frozen static scan of official BIPIA Email, Table, and Code test contexts "
                "with the official end-insertion construction. This measures external-content "
                "scanner generalization, not BIPIA response attack success and not Agent/tool "
                "end-to-end unauthorized-action blocking."
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
