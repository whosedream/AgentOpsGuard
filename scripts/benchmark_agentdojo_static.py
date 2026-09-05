#!/usr/bin/env python3
"""Regression-evaluate frozen AgentDojo templates without retaining raw text."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from agentops_guard.backend.services.semantic_scanner import (
    SEMANTIC_MANIFEST_SHA256,
    SEMANTIC_MODEL_ID,
)
from agentops_guard.benchmarks.llmail_inject import (
    DEFAULT_MODEL_PATH,
    DEFAULT_MODEL_SHA256,
    BenchmarkSample,
    EvaluationResult,
    _group_summary,
    evaluate_samples,
    file_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
EVAL_PYTHON = ROOT / "evals" / "inspect" / ".venv" / "bin" / "python"
EXPORTER = ROOT / "evals" / "inspect" / "export_agentdojo_static_cases.py"
EXPECTED_PACKAGE_VERSION = "0.1.35"
EXPECTED_BENCHMARK_VERSION = "v1.2.2"
EXPECTED_SUITES = {
    "banking": {"user_tasks": 16, "injection_tasks": 9, "tools": 11, "injection_vectors": 4},
    "slack": {"user_tasks": 21, "injection_tasks": 5, "tools": 11, "injection_vectors": 6},
    "travel": {"user_tasks": 20, "injection_tasks": 7, "tools": 28, "injection_vectors": 13},
    "workspace": {
        "user_tasks": 40,
        "injection_tasks": 14,
        "tools": 24,
        "injection_vectors": 16,
    },
}
EXPECTED_ATTACK_FAMILIES = {
    "direct",
    "ignore_previous",
    "injecagent",
    "system_message",
}
EXPECTED_ATTACK_ROWS = 140
EXPECTED_BENIGN_ROWS = 97
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks" / "agentdojo_static_regression_v2.json"


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


def _load_cases() -> tuple[list[BenchmarkSample], dict[str, Any], str]:
    if not EVAL_PYTHON.is_file():
        raise RuntimeError("isolated evaluation environment is not installed")
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
    if completed.returncode != 0:
        raise RuntimeError("AgentDojo case export failed")
    payload_bytes = completed.stdout.strip()
    payload = json.loads(payload_bytes)
    if payload.get("package_version") != EXPECTED_PACKAGE_VERSION:
        raise RuntimeError("unexpected AgentDojo package version")
    if payload.get("benchmark_version") != EXPECTED_BENCHMARK_VERSION:
        raise RuntimeError("unexpected AgentDojo benchmark version")
    if payload.get("suite_summary") != EXPECTED_SUITES:
        raise RuntimeError("AgentDojo suite inventory changed")

    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("AgentDojo exporter returned an invalid case list")
    case_ids: set[str] = set()
    family_counts: Counter[str] = Counter()
    samples: list[BenchmarkSample] = []
    for case in cases:
        if not isinstance(case, dict):
            raise RuntimeError("AgentDojo exporter returned an invalid case")
        case_id = case.get("case_id")
        kind = case.get("kind")
        family = case.get("family")
        content = case.get("content")
        if (
            not isinstance(case_id, str)
            or case_id in case_ids
            or kind not in {"attack", "benign"}
            or not isinstance(family, str)
            or not isinstance(content, str)
            or not content
        ):
            raise RuntimeError("AgentDojo case contract changed")
        case_ids.add(case_id)
        family_counts[family] += 1
        samples.append(BenchmarkSample(kind=kind, content=content, official_reason=family))

    attack_rows = sum(sample.kind == "attack" for sample in samples)
    benign_rows = sum(sample.kind == "benign" for sample in samples)
    if attack_rows != EXPECTED_ATTACK_ROWS or benign_rows != EXPECTED_BENIGN_ROWS:
        raise RuntimeError("AgentDojo selected row count changed")
    if {sample.official_reason for sample in samples if sample.kind == "attack"} != (
        EXPECTED_ATTACK_FAMILIES
    ):
        raise RuntimeError("AgentDojo attack family selection changed")
    return samples, payload["suite_summary"], hashlib.sha256(payload_bytes).hexdigest()


def _summary(results: list[EvaluationResult]) -> dict[str, Any]:
    attacks = [result for result in results if result.kind == "attack"]
    benign = [result for result in results if result.kind == "benign"]
    return {
        "attack": _group_summary(attacks),
        "attack_by_family": {
            family: _group_summary(
                [result for result in attacks if result.official_reason == family]
            )
            for family in sorted(EXPECTED_ATTACK_FAMILIES)
        },
        "benign": _group_summary(benign),
    }


def _source_hashes() -> dict[str, str]:
    paths = (
        "evals/inspect/export_agentdojo_static_cases.py",
        "evals/inspect/uv.lock",
        "scripts/benchmark_agentdojo_static.py",
        "src/agentops_guard/backend/services/policy.py",
        "src/agentops_guard/backend/services/scanner.py",
        "src/agentops_guard/backend/services/semantic_scanner.py",
        "src/agentops_guard/benchmarks/llmail_inject.py",
    )
    return {path: file_sha256(ROOT / path) for path in paths}


def _write_new_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--model-sha256", default=DEFAULT_MODEL_SHA256)
    parser.add_argument("--manifest-sha256", default=SEMANTIC_MANIFEST_SHA256)
    parser.add_argument("--threshold", type=float, default=0.90)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if not 0 < args.threshold < 1:
        parser.error("--threshold must be between 0 and 1")

    samples, suite_summary, corpus_sha256 = _load_cases()
    results = evaluate_samples(
        samples,
        model_path=args.model_path.resolve(),
        model_sha256=args.model_sha256,
        manifest_sha256=args.manifest_sha256,
        threshold=args.threshold,
        workers=args.workers,
    )
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
                "name": "AgentDojo",
                "package_version": EXPECTED_PACKAGE_VERSION,
                "benchmark_version": EXPECTED_BENCHMARK_VERSION,
                "license": "MIT",
                "source": "https://github.com/ethz-spylab/agentdojo",
                "suite_summary": suite_summary,
                "attack_families": sorted(EXPECTED_ATTACK_FAMILIES),
                "selected_attack_rows": EXPECTED_ATTACK_ROWS,
                "selected_benign_rows": EXPECTED_BENIGN_ROWS,
                "selected_corpus_sha256": corpus_sha256,
            },
            "model": {
                "id": SEMANTIC_MODEL_ID,
                "sha256": args.model_sha256,
                "manifest_sha256": args.manifest_sha256,
                "threshold": args.threshold,
                "mode": "shadow",
            },
            "implementation_sha256": _source_hashes(),
            "evidence_kind": "post_first_run_regression",
            "historical_first_run": {
                "report": "artifacts/benchmarks/agentdojo_static_blind_v1.json",
                "sha256": "84fc70e9df645e6f26b33957b57acc518ea0756361fa49e45b512dd2efc1583b",
            },
            "scope": (
                "Post-first-run static regression of four published AgentDojo attack templates "
                "combined with 35 published injection goals, plus 97 legitimate user-task prompts "
                "as hard clean controls. This is not a blind test or an AgentDojo end-to-end score."
            ),
            "privacy": {
                "stores_raw_cases": False,
                "stores_per_case_results": False,
                "stores_model_scores": False,
            },
        },
        "summary": _summary(results),
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
