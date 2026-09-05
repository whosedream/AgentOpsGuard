#!/usr/bin/env python3
"""Measure aggregate threshold trade-offs for the known-corpus windowing probe."""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from agentops_guard.backend.services.semantic_scanner import SEMANTIC_MANIFEST_SHA256
from agentops_guard.benchmarks.bipia import (
    DEFAULT_REPOSITORY,
    load_bipia_samples,
    summarize_bipia_results,
)
from agentops_guard.benchmarks.llmail_inject import (
    DEFAULT_MODEL_PATH,
    DEFAULT_MODEL_SHA256,
    BenchmarkSample,
    file_sha256,
)
from semantic_windowing_probe_lib import (
    BATCH_SIZE,
    MAX_CHUNKS,
    MAX_TOKENS,
    OVERLAP_TOKENS,
    evaluate_windowed_samples,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "evals" / "llama-cookbook-prompt-guard-source.json"
PROBE_V1 = ROOT / "artifacts" / "benchmarks" / "bipia_windowing_probe_v1.json"
PROBE_V1_SHA256 = "8be6408086557eacbd285adcb88985e543e5f9cd34d13015b2cd0c60e69b7e66"
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks" / "bipia_windowing_calibration_v1.json"
THRESHOLDS = (0.9, 0.95, 0.99, 0.995, 0.999)
EXPECTED_SAMPLE_SHA256 = "a8c338da654b80f568125418cb493e92ca2e51eff3bdcd3b634003a4dbf8de87"


def _probe_samples(samples: list[BenchmarkSample]) -> list[BenchmarkSample]:
    benign = [sample for sample in samples if sample.kind == "benign"]
    by_reason: dict[str, list[BenchmarkSample]] = {}
    for sample in samples:
        if sample.kind == "attack":
            by_reason.setdefault(sample.official_reason or "", []).append(sample)
    attacks = [sample for reason in sorted(by_reason) for sample in by_reason[reason][:5]]
    if len(attacks) != 200 or len(benign) != 200:
        raise RuntimeError("BIPIA calibration probe inventory changed")
    return attacks + benign


def _sample_digest(samples: list[BenchmarkSample]) -> str:
    digest = hashlib.sha256()
    for sample in samples:
        digest.update(
            json.dumps(
                [sample.kind, sample.official_reason, sample.content],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _implementation_hashes() -> dict[str, str]:
    paths = (
        "evals/bipia-source.json",
        "evals/llama-cookbook-prompt-guard-source.json",
        "scripts/benchmark_semantic_windowing_calibration.py",
        "scripts/semantic_windowing_probe_lib.py",
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
    parser = argparse.ArgumentParser(description="Calibrate the known BIPIA windowing probe")
    parser.add_argument("--bipia-repository", type=Path, default=DEFAULT_REPOSITORY)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if args.output.exists():
        parser.error("output already exists; calibration evidence is immutable")
    if file_sha256(PROBE_V1) != PROBE_V1_SHA256:
        raise RuntimeError("windowing probe v1 changed")

    all_samples, inventory = load_bipia_samples(args.bipia_repository)
    samples = _probe_samples(all_samples)
    if _sample_digest(samples) != EXPECTED_SAMPLE_SHA256:
        raise RuntimeError("BIPIA calibration sample changed")
    evaluations, chunks, scores = evaluate_windowed_samples(
        samples,
        model_path=args.model_path.resolve(),
        model_sha256=DEFAULT_MODEL_SHA256,
        manifest_sha256=SEMANTIC_MANIFEST_SHA256,
        threshold=0.9,
        workers=args.workers,
    )
    summaries = {}
    for threshold in THRESHOLDS:
        thresholded = [
            replace(evaluation, model_flagged=score >= threshold)
            for evaluation, score in zip(evaluations, scores, strict=True)
        ]
        summaries[str(threshold)] = summarize_bipia_results(thresholded)

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
                "name": "Microsoft BIPIA known calibration probe slice",
                "source_commit": "a004b69ec0dd446e0afd461d98cb5e96e120a5d0",
                "parent_corpus_sha256": inventory["selected_corpus_sha256"],
                "selected_corpus_sha256": EXPECTED_SAMPLE_SHA256,
                "attack_rows": 200,
                "benign_rows": 200,
            },
            "model": {
                "id": "patronus-studio/wolf-defender-prompt-injection-small",
                "sha256": DEFAULT_MODEL_SHA256,
                "manifest_sha256": SEMANTIC_MANIFEST_SHA256,
                "mode": "shadow_calibration_probe_only",
            },
            "windowing": {
                "max_tokens": MAX_TOKENS,
                "overlap_tokens": OVERLAP_TOKENS,
                "max_chunks": MAX_CHUNKS,
                "batch_size": BATCH_SIZE,
                "observed_chunks": chunks,
                "overflow_behavior": "fail",
                "adapted_from": json.loads(SOURCE_LOCK.read_text(encoding="utf-8")),
            },
            "thresholds": list(THRESHOLDS),
            "implementation_sha256": _implementation_hashes(),
            "evidence_kind": "post_holdout_in_sample_threshold_probe",
            "parent_probe": {
                "report": "artifacts/benchmarks/bipia_windowing_probe_v1.json",
                "sha256": PROBE_V1_SHA256,
            },
            "scope": (
                "Aggregate in-sample threshold exploration on the already known BIPIA probe slice. "
                "It may reject a design but cannot prove generalization, select a production "
                "threshold, or promote a model."
            ),
            "privacy": {
                "stores_raw_cases": False,
                "stores_per_case_results": False,
                "stores_model_scores": False,
                "stores_threshold_aggregates": True,
            },
        },
        "threshold_summaries": summaries,
    }
    _write_new_report(report, args.output)
    print(
        " ".join(
            f"t={threshold}:attack={summaries[str(threshold)]['attack']['combined_flagged']}/200:"
            f"benign={summaries[str(threshold)]['benign']['combined_flagged']}/200"
            for threshold in THRESHOLDS
        ),
        "report_created=true",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
