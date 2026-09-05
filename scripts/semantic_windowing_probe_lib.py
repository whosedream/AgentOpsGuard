"""Bounded long-text model probe adapted from Meta's Prompt Guard inference utility."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
import multiprocessing
import os
from pathlib import Path
import re
from threading import Lock
import time
import unicodedata

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.schemas import PolicyContext, ScanRequest
from agentops_guard.backend.services.content import redact_text
from agentops_guard.backend.services.policy import evaluate_builtin_policy
from agentops_guard.backend.services.semantic_scanner import (
    MODEL_SECRET_PATTERNS,
    SemanticScanner,
    SemanticScannerUnavailable,
)
from agentops_guard.benchmarks.llmail_inject import (
    IPI_RISK_LABELS,
    BenchmarkSample,
    EvaluationResult,
)


MAX_TOKENS = 512
OVERLAP_TOKENS = 64
MAX_CHUNKS = 16
BATCH_SIZE = 4


@dataclass(frozen=True)
class WindowedEvaluationResult:
    evaluation: EvaluationResult
    chunks: int
    model_score: float


def full_safe_model_text(text: str) -> str:
    """Apply the production secret boundary without its lossy 512-character sampling."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(
        character for character in normalized if unicodedata.category(character) != "Cf"
    )
    normalized = re.sub(
        r"[A-Za-z0-9+/=]{32,}",
        "[REDACTED:encoded_token]",
        normalized,
    )
    for pattern in MODEL_SECRET_PATTERNS:
        normalized = pattern.sub("[REDACTED:credential]", normalized)
    return redact_text(normalized) or ""


def chunk_start_indices(
    total_tokens: int,
    *,
    window_tokens: int,
    overlap_tokens: int,
    max_chunks: int,
) -> list[int]:
    if total_tokens < 0 or window_tokens <= 0 or max_chunks <= 0:
        raise ValueError("invalid semantic window limits")
    if not 0 <= overlap_tokens < window_tokens:
        raise ValueError("semantic window overlap must be smaller than its window")
    if total_tokens == 0:
        return [0]
    step = window_tokens - overlap_tokens
    starts = list(range(0, total_tokens, step))
    if len(starts) > 1 and starts[-1] + overlap_tokens >= total_tokens:
        starts.pop()
    if len(starts) > max_chunks:
        raise SemanticScannerUnavailable("semantic model coverage limit exceeded")
    return starts


class WindowedTransformersBackend:
    def __init__(self, model_path: Path) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise SemanticScannerUnavailable(
                "semantic scanner dependencies are not installed"
            ) from exc

        torch.set_num_threads(1)
        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_path,
            local_files_only=True,
            trust_remote_code=False,
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_path,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        ).eval()
        self._inference_lock = Lock()

    def predict(self, text: str) -> tuple[float, int]:
        if not self._inference_lock.acquire(blocking=False):
            raise SemanticScannerUnavailable("semantic model is busy")
        try:
            token_ids = self._tokenizer(
                text,
                add_special_tokens=False,
                truncation=False,
                return_attention_mask=False,
            )["input_ids"]
            special_tokens = self._tokenizer.num_special_tokens_to_add(pair=False)
            window_tokens = MAX_TOKENS - special_tokens
            starts = chunk_start_indices(
                len(token_ids),
                window_tokens=window_tokens,
                overlap_tokens=OVERLAP_TOKENS,
                max_chunks=MAX_CHUNKS,
            )
            chunks = [
                self._tokenizer.decode(
                    token_ids[start : start + window_tokens],
                    skip_special_tokens=True,
                )
                for start in starts
            ]
            highest_score = 0.0
            with self._torch.inference_mode():
                for start in range(0, len(chunks), BATCH_SIZE):
                    encoded = self._tokenizer(
                        chunks[start : start + BATCH_SIZE],
                        max_length=MAX_TOKENS,
                        padding=True,
                        return_tensors="pt",
                        truncation=True,
                    )
                    logits = self._model(**encoded).logits
                    scores = self._torch.softmax(logits, dim=-1)[:, 1]
                    highest_score = max(highest_score, float(scores.max().item()))
            return highest_score, len(chunks)
        finally:
            self._inference_lock.release()


_worker_backend: WindowedTransformersBackend | None = None


def _initialize_worker(
    model_path: str,
    model_sha256: str,
    manifest_sha256: str,
) -> None:
    global _worker_backend

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["AGENTOPS_SCANNER_PLUGINS"] = "[]"
    os.environ["AGENTOPS_SEMANTIC_SCANNER_MODE"] = "disabled"
    get_settings.cache_clear()
    from agentops_guard.backend.services import scanner as scanner_service

    scanner_service.get_semantic_scanner = lambda: None
    verified = SemanticScanner(
        Path(model_path),
        model_sha256,
        mode="shadow",
        threshold=0.9,
        manifest_sha256=manifest_sha256,
    )
    del verified
    _worker_backend = WindowedTransformersBackend(Path(model_path))


def _evaluate(sample: BenchmarkSample, threshold: float) -> WindowedEvaluationResult:
    from agentops_guard.backend.services.scanner import scan_content

    if _worker_backend is None:
        raise RuntimeError("windowing probe worker was not initialized")
    request = ScanRequest(
        content=sample.content,
        source="mcp_tool_result",
        metadata={"trust": "untrusted"},
    )
    regex_started = time.perf_counter_ns()
    scan = scan_content(request)
    regex_latency_ms = (time.perf_counter_ns() - regex_started) / 1_000_000
    model_started = time.perf_counter_ns()
    score, chunks = _worker_backend.predict(full_safe_model_text(request.content))
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
    return WindowedEvaluationResult(
        evaluation=EvaluationResult(
            kind=sample.kind,
            official_reason=sample.official_reason,
            regex_flagged=bool(set(scan.risk_labels) & IPI_RISK_LABELS),
            any_rule_risk=bool(scan.risk_labels),
            model_flagged=score >= threshold,
            policy_action=policy.action,
            regex_latency_ms=regex_latency_ms,
            model_latency_ms=model_latency_ms,
        ),
        chunks=chunks,
        model_score=score,
    )


def evaluate_windowed_samples(
    samples: list[BenchmarkSample],
    *,
    model_path: Path,
    model_sha256: str,
    manifest_sha256: str,
    threshold: float,
    workers: int,
) -> tuple[list[EvaluationResult], dict[str, int], list[float]]:
    context = multiprocessing.get_context("spawn")
    wrapped: list[WindowedEvaluationResult] = []
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=context,
        initializer=_initialize_worker,
        initargs=(str(model_path), model_sha256, manifest_sha256),
    ) as executor:
        arguments = ((sample, threshold) for sample in samples)
        for index, result in enumerate(
            executor.map(_evaluate_from_tuple, arguments, chunksize=8), start=1
        ):
            wrapped.append(result)
            if index % 250 == 0 or index == len(samples):
                print(f"windowed_evaluated {index}/{len(samples)}", flush=True)
    return (
        [result.evaluation for result in wrapped],
        dict(sorted(Counter(str(result.chunks) for result in wrapped).items())),
        [result.model_score for result in wrapped],
    )


def _evaluate_from_tuple(
    arguments: tuple[BenchmarkSample, float],
) -> WindowedEvaluationResult:
    return _evaluate(*arguments)
