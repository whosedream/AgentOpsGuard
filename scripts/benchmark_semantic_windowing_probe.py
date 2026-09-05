#!/usr/bin/env python3
"""Compare legacy character sampling with bounded full-token windowing on known BIPIA data."""

from __future__ import annotations

import argparse
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
    evaluate_samples,
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
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks" / "bipia_windowing_probe_v1.json"
BASELINE_REPORT = ROOT / "artifacts" / "benchmarks" / "bipia_static_holdout_v1.json"
BASELINE_REPORT_SHA256 = (
    "4e9bb897996d85cad3e7bc15859abecd6b361a448d1e30a22e9a1063f74e53e6"
)


def _probe_samples(samples: list[BenchmarkSample]) -> list[BenchmarkSample]:
    benign = [sample for sample in samples if sample.kind == "benign"]
    attacks = [sample for sample in samples if sample.kind == "attack"]
    by_reason: dict[str, list[BenchmarkSample]] = {}
    for sample in attacks:
        reason = sample.official_reason or ""
        by_reason.setdefault(reason, []).append(sample)
    selected_attacks = [sample for reason in sorted(by_reason) for sample in by_reason[reason][:5]]
    if len(benign) != 200 or len(selected_attacks) != 200:
        raise RuntimeError("BIPIA windowing probe inventory changed")
    return selected_attacks + benign


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
        "scripts/benchmark_semantic_windowing_probe.py",
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
    parser = argparse.ArgumentParser(description="Probe full-token semantic windowing")
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
        parser.error("output already exists; probe evidence is immutable")
    if file_sha256(BASELINE_REPORT) != BASELINE_REPORT_SHA256:
        raise RuntimeError("BIPIA first-run baseline changed")

    all_samples, inventory = load_bipia_samples(args.bipia_repository)
    samples = _probe_samples(all_samples)
    sample_sha256 = _sample_digest(samples)
    legacy = evaluate_samples(
        samples,
        model_path=args.model_path.resolve(),
        model_sha256=DEFAULT_MODEL_SHA256,
        manifest_sha256=SEMANTIC_MANIFEST_SHA256,
        threshold=args.threshold,
        workers=args.workers,
    )
    windowed, chunks, _scores = evaluate_windowed_samples(
        samples,
        model_path=args.model_path.resolve(),
        model_sha256=DEFAULT_MODEL_SHA256,
        manifest_sha256=SEMANTIC_MANIFEST_SHA256,
        threshold=args.threshold,
        workers=args.workers,
    )
    source_lock = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
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
                "name": "Microsoft BIPIA known probe slice",
                "source_commit": "a004b69ec0dd446e0afd461d98cb5e96e120a5d0",
                "parent_corpus_sha256": inventory["selected_corpus_sha256"],
                "selected_corpus_sha256": sample_sha256,
                "attack_rows": 200,
                "benign_rows": 200,
                "selection": "first five combinations per sorted task/family plus all benign",
            },
            "model": {
                "id": "patronus-studio/wolf-defender-prompt-injection-small",
                "sha256": DEFAULT_MODEL_SHA256,
                "manifest_sha256": SEMANTIC_MANIFEST_SHA256,
                "threshold": args.threshold,
                "mode": "shadow_probe_only",
            },
            "windowing": {
                "max_tokens": MAX_TOKENS,
                "overlap_tokens": OVERLAP_TOKENS,
                "max_chunks": MAX_CHUNKS,
                "batch_size": BATCH_SIZE,
                "observed_chunks": chunks,
                "overflow_behavior": "fail",
                "adapted_from": source_lock,
            },
            "implementation_sha256": _implementation_hashes(),
            "evidence_kind": "post_holdout_architecture_probe",
            "baseline": {
                "report": "artifacts/benchmarks/bipia_static_holdout_v1.json",
                "sha256": BASELINE_REPORT_SHA256,
            },
            "scope": (
                "Known-corpus architecture probe comparing current 512-character sampling with "
                "full sanitized token windowing. It is not blind, not a production change, and "
                "not model-promotion evidence."
            ),
            "privacy": {
                "stores_raw_cases": False,
                "stores_per_case_results": False,
                "stores_model_scores": False,
            },
        },
        "legacy": summarize_bipia_results(legacy),
        "windowed": summarize_bipia_results(windowed),
    }
    _write_new_report(report, args.output)
    old_attack = report["legacy"]["attack"]
    new_attack = report["windowed"]["attack"]
    old_benign = report["legacy"]["benign"]
    new_benign = report["windowed"]["benign"]
    print(
        f"legacy_attack={old_attack['combined_flagged']}/{old_attack['rows']} "
        f"windowed_attack={new_attack['combined_flagged']}/{new_attack['rows']} "
        f"legacy_benign={old_benign['combined_flagged']}/{old_benign['rows']} "
        f"windowed_benign={new_benign['combined_flagged']}/{new_benign['rows']} "
        "report_created=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
