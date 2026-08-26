from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import platform
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.schemas import PolicyContext, ScanRequest
from agentops_guard.backend.services.policy import evaluate_builtin_policy
from agentops_guard.backend.services.semantic_scanner import (
    SEMANTIC_MANIFEST_SHA256,
    SEMANTIC_MODEL_ID,
    SemanticScanner,
)


DATASET_NAME = "microsoft/llmail-inject-challenge"
DATASET_REVISION = "1063bdf01ec8762b812d5e06ee768a06faa5a6f7"
ATTACK_SHA256 = "f89af984e345430c3b357903890e30867bf4676f4ef10c138cc7bad218e890b8"
BENIGN_SHA256 = "4ddd950b5dbaa8548f5597c886d8e09a051ba07f80a9291fdcca9c2397d22abe"
ATTACK_ROWS = 21_007
BENIGN_ROWS = 203
DEFAULT_DATASET_DIRECTORY = (
    Path.home() / ".cache/huggingface/agentops-guard-benchmarks/llmail-inject-phase2"
)
DEFAULT_MODEL_PATH = Path("models/semantic-guard")
DEFAULT_MODEL_SHA256 = "0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0"
DEFAULT_OUTPUT_PATH = Path("artifacts/benchmarks/llmail_inject_phase2_v1.json")
IPI_RISK_LABELS = frozenset(
    {
        "base64_obfuscation",
        "credential_exfiltration",
        "data_exfiltration",
        "hidden_html",
        "instruction_override",
        "markdown_link_trap",
        "system_prompt_override",
        "tool_hijacking",
    }
)


@dataclass(frozen=True)
class BenchmarkSample:
    kind: str
    content: str
    official_reason: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    kind: str
    official_reason: str | None
    regex_flagged: bool
    any_rule_risk: bool
    model_flagged: bool
    policy_action: str
    regex_latency_ms: float
    model_latency_ms: float


_worker_semantic_scanner: SemanticScanner | None = None


def file_sha256(path: Path) -> str:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def load_samples(
    attack_path: Path,
    benign_path: Path,
    *,
    expected_attack_sha256: str = ATTACK_SHA256,
    expected_benign_sha256: str = BENIGN_SHA256,
    expected_attack_rows: int = ATTACK_ROWS,
    expected_benign_rows: int = BENIGN_ROWS,
) -> list[BenchmarkSample]:
    actual_attack_sha256 = file_sha256(attack_path)
    if actual_attack_sha256 != expected_attack_sha256:
        raise ValueError(
            "attack dataset SHA-256 mismatch: "
            f"expected {expected_attack_sha256}, got {actual_attack_sha256}"
        )
    actual_benign_sha256 = file_sha256(benign_path)
    if actual_benign_sha256 != expected_benign_sha256:
        raise ValueError(
            "benign dataset SHA-256 mismatch: "
            f"expected {expected_benign_sha256}, got {actual_benign_sha256}"
        )

    attack_data = json.loads(attack_path.read_text(encoding="utf-8"))
    if not isinstance(attack_data, dict):
        raise ValueError("attack dataset must be a JSON object")
    attacks = [
        BenchmarkSample(
            kind="attack",
            content=content,
            official_reason=str(labels["reason"]),
        )
        for content, labels in attack_data.items()
        if isinstance(content, str)
        and isinstance(labels, dict)
        and (labels.get("attack_attempt") is True or labels.get("attack_attempt") == "True")
    ]
    if len(attacks) != expected_attack_rows:
        raise ValueError(
            f"selected attack row mismatch: expected {expected_attack_rows}, got {len(attacks)}"
        )
    unknown_reasons = sorted(
        {sample.official_reason for sample in attacks} - {"api_triggered", "judge"}
    )
    if unknown_reasons:
        raise ValueError(f"unexpected official reason: {unknown_reasons[0]}")

    benign_data = json.loads(benign_path.read_text(encoding="utf-8"))
    if not isinstance(benign_data, list) or not all(
        isinstance(content, str) for content in benign_data
    ):
        raise ValueError("benign dataset must be a JSON string list")
    if len(benign_data) != expected_benign_rows:
        raise ValueError(
            f"benign row mismatch: expected {expected_benign_rows}, got {len(benign_data)}"
        )
    return attacks + [BenchmarkSample(kind="benign", content=content) for content in benign_data]


def _initialize_worker(
    model_path: str,
    model_sha256: str,
    manifest_sha256: str,
    threshold: float,
) -> None:
    global _worker_semantic_scanner

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["AGENTOPS_SCANNER_PLUGINS"] = "[]"
    os.environ["AGENTOPS_SEMANTIC_SCANNER_MODE"] = "disabled"
    get_settings.cache_clear()

    from agentops_guard.backend.services import scanner as scanner_service

    scanner_service.get_semantic_scanner = lambda: None
    _worker_semantic_scanner = SemanticScanner(
        model_path=Path(model_path),
        model_sha256=model_sha256,
        mode="shadow",
        threshold=threshold,
        manifest_sha256=manifest_sha256,
    )
    _worker_semantic_scanner.warm()


def _evaluate_sample(sample: BenchmarkSample) -> EvaluationResult:
    from agentops_guard.backend.services.scanner import scan_content

    if _worker_semantic_scanner is None:
        raise RuntimeError("benchmark worker was not initialized")

    request = ScanRequest(
        content=sample.content,
        source="mcp_tool_result",
        metadata={"trust": "untrusted"},
    )
    regex_started = time.perf_counter_ns()
    scan = scan_content(request)
    regex_latency_ms = (time.perf_counter_ns() - regex_started) / 1_000_000

    model_started = time.perf_counter_ns()
    assessment = _worker_semantic_scanner.assess(request)
    model_latency_ms = (time.perf_counter_ns() - model_started) / 1_000_000

    policy = evaluate_builtin_policy(
        PolicyContext(
            risk_score=scan.risk_score,
            risk_labels=scan.risk_labels,
            data={
                "labels": scan.risk_labels,
                "content_source": "mcp_tool_result",
                "trust": "untrusted",
            },
        )
    )
    return EvaluationResult(
        kind=sample.kind,
        official_reason=sample.official_reason,
        regex_flagged=bool(set(scan.risk_labels) & IPI_RISK_LABELS),
        any_rule_risk=bool(scan.risk_labels),
        model_flagged=assessment is not None and assessment.label == "prompt_injection",
        policy_action=policy.action,
        regex_latency_ms=regex_latency_ms,
        model_latency_ms=model_latency_ms,
    )


def wilson_interval(successes: int, total: int) -> list[float]:
    if total <= 0:
        raise ValueError("Wilson interval requires a positive denominator")
    z = 1.959963984540054
    observed = successes / total
    denominator = 1 + z * z / total
    centre = observed + z * z / (2 * total)
    margin = z * math.sqrt(observed * (1 - observed) / total + z * z / (4 * total * total))
    return [round((centre - margin) / denominator, 6), round((centre + margin) / denominator, 6)]


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * quantile) - 1]


def _group_summary(results: list[EvaluationResult]) -> dict[str, Any]:
    rows = len(results)
    regex_flagged = sum(result.regex_flagged for result in results)
    model_flagged = sum(result.model_flagged for result in results)
    combined_flagged = sum(result.regex_flagged or result.model_flagged for result in results)
    return {
        "rows": rows,
        "regex_flagged": regex_flagged,
        "regex_rate": regex_flagged / rows,
        "model_flagged": model_flagged,
        "model_rate": model_flagged / rows,
        "combined_flagged": combined_flagged,
        "combined_rate": combined_flagged / rows,
        "combined_rate_wilson_95": wilson_interval(combined_flagged, rows),
        "any_rule_risk": sum(result.any_rule_risk for result in results),
        "rule_policy_actions": dict(
            sorted(Counter(result.policy_action for result in results).items())
        ),
        "latency_ms": {
            "regex": {
                "p50": percentile([result.regex_latency_ms for result in results], 0.50),
                "p95": percentile([result.regex_latency_ms for result in results], 0.95),
            },
            "model": {
                "p50": percentile([result.model_latency_ms for result in results], 0.50),
                "p95": percentile([result.model_latency_ms for result in results], 0.95),
            },
            "combined_sequential": {
                "p50": percentile(
                    [result.regex_latency_ms + result.model_latency_ms for result in results], 0.50
                ),
                "p95": percentile(
                    [result.regex_latency_ms + result.model_latency_ms for result in results], 0.95
                ),
            },
        },
    }


def summarize_results(results: list[EvaluationResult]) -> dict[str, Any]:
    attacks = [result for result in results if result.kind == "attack"]
    benign = [result for result in results if result.kind == "benign"]
    if not attacks or not benign:
        raise ValueError("benchmark requires both attack and benign results")
    reason_slices = {
        reason: _group_summary(
            [result for result in attacks if result.official_reason == reason]
        )
        for reason in ("api_triggered", "judge")
    }
    return {
        "attack": _group_summary(attacks),
        "attack_by_official_reason": reason_slices,
        "benign": _group_summary(benign),
    }


def evaluate_samples(
    samples: list[BenchmarkSample],
    *,
    model_path: Path,
    model_sha256: str,
    manifest_sha256: str,
    threshold: float,
    workers: int,
) -> list[EvaluationResult]:
    context = multiprocessing.get_context("spawn")
    results: list[EvaluationResult] = []
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=context,
        initializer=_initialize_worker,
        initargs=(str(model_path), model_sha256, manifest_sha256, threshold),
    ) as executor:
        for index, result in enumerate(executor.map(_evaluate_sample, samples, chunksize=16), start=1):
            results.append(result)
            if index % 1_000 == 0 or index == len(samples):
                print(f"evaluated {index}/{len(samples)}", flush=True)
    return results


def _implementation_hashes(repository_root: Path, paths: Iterable[str]) -> dict[str, str]:
    return {path: file_sha256(repository_root / path) for path in paths}


def build_report(
    summary: dict[str, Any],
    *,
    repository_root: Path,
    workers: int,
    threshold: float,
    attack_path: Path,
    benign_path: Path,
) -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        cwd=repository_root,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
            cwd=repository_root,
        ).stdout
    )
    implementation_paths = (
        "pyproject.toml",
        "scripts/run_llmail_benchmark.py",
        "src/agentops_guard/backend/schemas.py",
        "src/agentops_guard/backend/services/content.py",
        "src/agentops_guard/backend/services/policy.py",
        "src/agentops_guard/backend/services/scanner.py",
        "src/agentops_guard/backend/services/semantic_scanner.py",
        "src/agentops_guard/benchmarks/llmail_inject.py",
        "uv.lock",
    )
    return {
        "metadata": {
            "created_at": datetime.now(UTC).isoformat(),
            "git_commit": commit,
            "git_dirty": dirty,
            "runtime": {
                "python": sys.version,
                "platform": platform.platform(),
                "workers": workers,
            },
            "implementation_sha256": _implementation_hashes(
                repository_root, implementation_paths
            ),
            "dataset": {
                "name": DATASET_NAME,
                "creator": "Microsoft",
                "revision": DATASET_REVISION,
                "phase": 2,
                "license": "MIT",
                "dataset_url": "https://huggingface.co/datasets/microsoft/llmail-inject-challenge",
                "paper_url": "https://arxiv.org/abs/2506.09956",
                "analysis_url": "https://github.com/microsoft/llmail-inject-challenge-analysis",
                "attack_file": {
                    "name": attack_path.name,
                    "sha256": ATTACK_SHA256,
                    "selection": "attack_attempt is boolean true or string True",
                },
                "benign_file": {"name": benign_path.name, "sha256": BENIGN_SHA256},
                "changes": (
                    "Selected official Phase 2 attack-attempt labels and emitted aggregate metrics; "
                    "no raw text, per-row result, or model score was copied into the report."
                ),
            },
            "evaluation": {
                "content_source": "mcp_tool_result",
                "trust": "untrusted",
                "semantic_mode": "shadow",
                "semantic_model": SEMANTIC_MODEL_ID,
                "semantic_threshold": threshold,
                "scope": (
                    "Static external-content scan plus rule-only built-in policy; no agent or tool "
                    "execution. Semantic results did not alter policy actions."
                ),
                "label_boundary": {
                    "api_triggered": "The challenge API was triggered in the source evaluation.",
                    "judge": "The source dataset's judge labelled the submission as an attack attempt.",
                },
                "interpretation": (
                    "Current reproducibility rerun on previously used challenge data. It is not a new "
                    "blind test and does not measure AgentOps Guard end-to-end unauthorized-action blocking."
                ),
            },
        },
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the fixed LLMail-Inject Phase 2 benchmark")
    parser.add_argument(
        "--attack-data",
        type=Path,
        default=DEFAULT_DATASET_DIRECTORY / "labelled_unique_submissions_phase2.json",
    )
    parser.add_argument(
        "--benign-data",
        type=Path,
        default=DEFAULT_DATASET_DIRECTORY / "emails_for_fp_tests.json",
    )
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--model-sha256", default=DEFAULT_MODEL_SHA256)
    parser.add_argument("--manifest-sha256", default=SEMANTIC_MANIFEST_SHA256)
    parser.add_argument("--threshold", type=float, default=0.90)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if not 0 < args.threshold < 1:
        parser.error("--threshold must be between 0 and 1")

    repository_root = Path(__file__).resolve().parents[3]
    model_path = args.model_path.resolve()
    samples = load_samples(args.attack_data, args.benign_data)
    results = evaluate_samples(
        samples,
        model_path=model_path,
        model_sha256=args.model_sha256,
        manifest_sha256=args.manifest_sha256,
        threshold=args.threshold,
        workers=args.workers,
    )
    summary = summarize_results(results)
    report = build_report(
        summary,
        repository_root=repository_root,
        workers=args.workers,
        threshold=args.threshold,
        attack_path=args.attack_data,
        benign_path=args.benign_data,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    attack = summary["attack"]
    api_triggered = summary["attack_by_official_reason"]["api_triggered"]
    benign = summary["benign"]
    print(
        f"attack combined detection: {attack['combined_rate']:.2%} "
        f"({attack['combined_flagged']}/{attack['rows']})"
    )
    print(
        f"api-triggered combined detection: {api_triggered['combined_rate']:.2%} "
        f"({api_triggered['combined_flagged']}/{api_triggered['rows']})"
    )
    print(
        f"benign combined false positives: {benign['combined_rate']:.2%} "
        f"({benign['combined_flagged']}/{benign['rows']})"
    )
    print(f"report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
