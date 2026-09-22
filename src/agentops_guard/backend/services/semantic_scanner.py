from __future__ import annotations

import hashlib
import json
import logging
import re
import random
import unicodedata
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from threading import BoundedSemaphore, Lock
from typing import Protocol

import httpx
import anyio

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.observability import (
    SEMANTIC_SCORING_FAILURES_COUNTER, SEMANTIC_SCORING_REQUESTS_COUNTER,
)
from agentops_guard.backend.schemas import ScanRequest, SemanticAssessment
from agentops_guard.backend.services.content import redact_text


SEMANTIC_MODEL_ID = (
    "patronus-studio/wolf-defender-prompt-injection-small@"
    "eff31df5c97ca127b7b55da255a160f88a625c97"
)
SEMANTIC_MANIFEST_SHA256 = "06bcefdafa24f95cd9901d8a46ec0f295ac144e89c9618197733948987c3bec4"
_scanner_creation_lock = Lock()
logger = logging.getLogger(__name__)
MAX_MODEL_CHARACTERS = 1_024
MAX_MODEL_WINDOWS = 2
MODEL_BATCH_SIZE = 1
INFERENCE_QUEUE_CAPACITY = 8
# A long-text inference takes about 0.6 s on the measured CPU. Let one such
# predecessor finish, but keep a bounded wait within the 2 s remote deadline.
INFERENCE_QUEUE_WAIT_SECONDS = 1.0
SEMANTIC_FAILURE_REASONS = frozenset({
    "unavailable", "overloaded", "queue_timeout", "inference_failed", "warmup_failed",
    "proxy_unavailable", "proxy_queue_timeout", "proxy_connection_failed",
})
SEMANTIC_SOURCES = frozenset(
    {
        "external",
        "mcp_prompt",
        "mcp_resource",
        "mcp_tool_result",
    }
)
MODEL_SECRET_PATTERNS = (
    re.compile(
        r"\b(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|"
        r"X-Auth-Token)\s*:\s*[^\r\n]+",
        re.I,
    ),
    re.compile(
        r"\bAuthorization\s*[:=]\s*[A-Za-z][A-Za-z0-9_-]*\s+[^\s,;]+",
        re.I,
    ),
    re.compile(
        r"(?<![A-Za-z0-9_-])(?:[A-Za-z][A-Za-z0-9_-]*[_-])?"
        r"(?:password|passwd|pwd|secret|key|token|credential)\s*[:=]\s*"
        r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)",
        re.I,
    ),
    re.compile(
        r"\bBearer\s+[^\s,;]+",
        re.I,
    ),
    re.compile(
        r"(?:\b(?:password|passwd|pwd|secret|api[_ -]?key|access[_ -]?token|"
        r"refresh[_ -]?token|authorization)\b\s*[:=]\s*"
        r"|(?:密码|口令|密钥)\s*[:=：]\s*)"
        r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)",
        re.I,
    ),
    re.compile(
        r"(?:\b(?:password|passcode|secret|token|api[_ -]?key)\b\s+"
        r"(?:is|equals?)\s+|(?:密码|口令|密钥)\s*(?:是|为)\s*)"
        r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)",
        re.I,
    ),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@", re.I),
)


class SemanticScannerUnavailable(RuntimeError):
    def __init__(self, message: str, *, reason: str = "unavailable", attempts: int = 1,
                 attempt_errors: tuple[str, ...] = (), retryable: bool = False) -> None:
        super().__init__(message)
        self.reason = reason
        self.attempts = attempts
        self.attempt_errors = attempt_errors or (reason,)
        self.retryable = retryable


class SemanticBackend(Protocol):
    def predict(self, text: str) -> float: ...


class TransformersSemanticBackend:
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
        self._inference_slots = BoundedSemaphore(INFERENCE_QUEUE_CAPACITY + 1)

    def predict(self, text: str) -> float:
        if not self._inference_slots.acquire(blocking=False):
            raise SemanticScannerUnavailable("semantic model queue is full", reason="overloaded")
        acquired = False
        try:
            acquired = self._inference_lock.acquire(timeout=INFERENCE_QUEUE_WAIT_SECONDS)
            if not acquired:
                raise SemanticScannerUnavailable("semantic model queue wait expired", reason="queue_timeout")
            return self._predict_locked(text)
        finally:
            if acquired:
                self._inference_lock.release()
            self._inference_slots.release()

    def _predict_locked(self, text: str) -> float:
        text = _bounded_model_text(text)
        encoded = self._tokenizer(
            text,
            max_length=2_048,
            padding=True,
            return_overflowing_tokens=True,
            return_tensors="pt",
            stride=128,
            truncation=True,
        )
        encoded.pop("overflow_to_sample_mapping", None)
        window_count = len(encoded["input_ids"])
        if window_count > MAX_MODEL_WINDOWS:
            indices = [
                round(index * (window_count - 1) / (MAX_MODEL_WINDOWS - 1))
                for index in range(MAX_MODEL_WINDOWS)
            ]
            encoded = {
                key: _select_rows(value, indices)
                for key, value in encoded.items()
            }
            window_count = MAX_MODEL_WINDOWS

        highest_score = 0.0
        with self._torch.inference_mode():
            for start in range(0, window_count, MODEL_BATCH_SIZE):
                batch = {
                    key: value[start : start + MODEL_BATCH_SIZE]
                    for key, value in encoded.items()
                }
                logits = self._model(**batch).logits
                scores = self._torch.softmax(logits, dim=-1)[:, 1]
                highest_score = max(highest_score, float(scores.max().item()))
        return highest_score


class SemanticScanner:
    def __init__(
        self,
        model_path: Path,
        model_sha256: str,
        mode: str,
        threshold: float,
        backend_factory: Callable[[Path], SemanticBackend] = TransformersSemanticBackend,
        manifest_sha256: str = SEMANTIC_MANIFEST_SHA256,
    ) -> None:
        manifest_file = model_path / "manifest.json"
        if not model_path.is_absolute() or not manifest_file.is_file():
            raise SemanticScannerUnavailable("semantic model directory is unavailable")
        if _file_sha256(manifest_file) != manifest_sha256:
            raise SemanticScannerUnavailable("semantic model manifest does not match reviewed assets")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        file_hashes = manifest["files"]
        if file_hashes["model.safetensors"] != model_sha256:
            raise SemanticScannerUnavailable("semantic model SHA-256 does not match configuration")
        allowed_files = set(file_hashes) | {".gitignore", "LICENSE", "README.md", "manifest.json"}
        unexpected_files = sorted(
            path.name
            for path in model_path.iterdir()
            if path.is_file() and path.name not in allowed_files
        )
        if unexpected_files:
            raise SemanticScannerUnavailable(
                f"semantic model directory contains unreviewed asset: {unexpected_files[0]}"
            )
        for filename, expected_sha256 in file_hashes.items():
            model_file = model_path / filename
            if not model_file.is_file() or _file_sha256(model_file) != expected_sha256:
                raise SemanticScannerUnavailable(
                    f"semantic model asset failed integrity check: {filename}"
                )
        self.model_path = model_path
        self.mode = mode
        self.threshold = threshold
        self._backend_factory = backend_factory
        self._backend: SemanticBackend | None = None
        self._backend_lock = Lock()
        self._warm_lock = Lock()
        self._warmed = False

    @property
    def backend(self) -> SemanticBackend:
        # Python 3.12 cached_property does not serialize concurrent first access.
        with self._backend_lock:
            if self._backend is None:
                self._backend = self._backend_factory(self.model_path)
            return self._backend

    def assess(self, request: ScanRequest) -> SemanticAssessment | None:
        if request.source not in SEMANTIC_SOURCES:
            return None
        safe_text = _safe_model_text(request.content)
        try:
            score = self.backend.predict(safe_text)
        except SemanticScannerUnavailable:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise SemanticScannerUnavailable("semantic model inference failed", reason="inference_failed") from exc
        return SemanticAssessment(
            status="ok",
            mode=self.mode,
            label="prompt_injection" if score >= self.threshold else "benign",
            score=score,
            model=SEMANTIC_MODEL_ID,
        )

    def warm(self) -> None:
        with self._warm_lock:
            if self._warmed:
                return
            try:
                self.backend.predict("health check")
            except SemanticScannerUnavailable:
                raise
            except (OSError, RuntimeError, ValueError) as exc:
                raise SemanticScannerUnavailable("semantic model warmup failed", reason="warmup_failed") from exc
            self._warmed = True


class RemoteSemanticScanner:
    def __init__(self, service_url: str, mode: str, threshold: float, timeout: float) -> None:
        self.service_url = service_url.rstrip("/")
        self.mode = mode
        self.threshold = threshold
        self.timeout = timeout

    def assess(self, request: ScanRequest) -> SemanticAssessment | None:
        if request.source not in SEMANTIC_SOURCES:
            return None
        try:
            score, errors = anyio.run(self._score, _safe_model_text(request.content))
        except SemanticScannerUnavailable:
            SEMANTIC_SCORING_REQUESTS_COUNTER.labels(outcome="error").inc()
            raise
        SEMANTIC_SCORING_REQUESTS_COUNTER.labels(outcome="recovered" if errors else "ok").inc()
        return SemanticAssessment(
            status="ok",
            mode=self.mode,
            label="prompt_injection" if score >= self.threshold else "benign",
            score=score,
            model=SEMANTIC_MODEL_ID,
            attempts=1 + len(errors),
            attempt_errors=errors,
        )

    def warm(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
                response = client.get(f"{self.service_url}/readyz")
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise SemanticScannerUnavailable("semantic model service is unavailable") from exc

    async def _score(self, text: str) -> tuple[float, list[str]]:
        # One overall deadline covers BOTH attempts, connection setup and backoff.
        # This retries only pure scoring of the same redacted input, never a tool.
        errors: list[str] = []
        attempts = 0
        try:
            with anyio.fail_after(self.timeout):
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
                    for attempts in (1, 2):
                        try:
                            return await self._score_once(client, text), errors
                        except SemanticScannerUnavailable as exc:
                            errors.append(exc.reason)
                            SEMANTIC_SCORING_FAILURES_COUNTER.labels(reason=exc.reason).inc()
                            # Fixed categories only: never log input, URL or exception text.
                            logger.info("semantic_score_attempt_failed reason=%s attempt=%d", exc.reason, attempts)
                            if attempts == 2 or not exc.retryable:
                                raise SemanticScannerUnavailable("semantic scoring failed", reason=exc.reason,
                                    attempts=attempts, attempt_errors=tuple(errors)) from exc
                            # Jitter limits synchronized retries; no backlog expansion.
                            await anyio.sleep(random.uniform(0.03, 0.07))
        except TimeoutError as exc:
            SEMANTIC_SCORING_FAILURES_COUNTER.labels(reason="deadline_exceeded").inc()
            raise SemanticScannerUnavailable("semantic scoring deadline exceeded", reason="deadline_exceeded",
                attempts=max(attempts, 1), attempt_errors=tuple((errors + ["deadline_exceeded"])[-2:])) from exc
        raise AssertionError("bounded scoring loop must return or raise")

    async def _score_once(self, client: httpx.AsyncClient, text: str) -> float:
        try:
            response = await client.post(f"{self.service_url}/v1/score", json={"text": text})
            if response.status_code == 503:
                # A proxy may return an empty/HTML 503. Do not depend on its body.
                try:
                    payload = response.json()
                except ValueError:
                    payload = None
                detail = payload.get("detail") if isinstance(payload, dict) else None
                code = detail.get("code") if isinstance(detail, dict) else None
                reason = code if isinstance(code, str) and code in SEMANTIC_FAILURE_REASONS else "unavailable"
                if reason == "proxy_unavailable":
                    termination = detail.get("termination")
                    reason = {"sQ": "proxy_queue_timeout", "SC": "proxy_connection_failed",
                              "sC": "proxy_connection_failed"}.get(
                                  termination if isinstance(termination, str) else "", reason)
                raise SemanticScannerUnavailable("semantic model service unavailable", reason=reason,
                    retryable=reason in {"unavailable", "overloaded", "queue_timeout",
                                         "proxy_unavailable", "proxy_queue_timeout", "proxy_connection_failed"})
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or isinstance(result.get("score"), bool):
                raise ValueError("invalid semantic service response")
            score = float(result["score"])
            if result.get("model") != SEMANTIC_MODEL_ID or not 0.0 <= score <= 1.0:
                raise ValueError("invalid semantic service response")
            return score
        except httpx.HTTPStatusError as exc:
            raise SemanticScannerUnavailable("semantic service HTTP error", reason="http_error",
                retryable=exc.response.status_code in {502, 504}) from exc
        except httpx.RequestError as exc:
            reason = next((label for kind, label in (
                (httpx.ConnectTimeout, "connect_timeout"), (httpx.ReadTimeout, "read_timeout"),
                (httpx.WriteTimeout, "write_timeout"), (httpx.PoolTimeout, "pool_timeout"),
                (httpx.ConnectError, "connection_failed"),
            ) if isinstance(exc, kind)), "transport_error")
            raise SemanticScannerUnavailable("semantic service transport failed", reason=reason,
                retryable=isinstance(exc, (httpx.NetworkError, httpx.TimeoutException, httpx.RemoteProtocolError))) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise SemanticScannerUnavailable("invalid semantic service response", reason="invalid_response") from exc


def get_semantic_scanner() -> SemanticScanner | RemoteSemanticScanner | None:
    settings = get_settings()
    if settings.semantic_scanner_mode == "disabled":
        return None
    if settings.semantic_service_url is not None:
        return _cached_remote_semantic_scanner(
            settings.semantic_service_url,
            settings.semantic_scanner_mode,
            settings.semantic_scanner_threshold,
            settings.semantic_service_timeout_seconds,
        )
    assert settings.semantic_model_path is not None
    with _scanner_creation_lock:
        return _cached_semantic_scanner(
            str(settings.semantic_model_path),
            settings.semantic_model_sha256 or "",
            settings.semantic_scanner_mode,
            settings.semantic_scanner_threshold,
        )


@lru_cache
def _cached_semantic_scanner(
    model_path: str,
    model_sha256: str,
    mode: str,
    threshold: float,
) -> SemanticScanner:
    return SemanticScanner(Path(model_path), model_sha256, mode, threshold)


@lru_cache
def _cached_remote_semantic_scanner(
    service_url: str,
    mode: str,
    threshold: float,
    timeout: float,
) -> RemoteSemanticScanner:
    return RemoteSemanticScanner(service_url, mode, threshold, timeout)


def semantic_scanner_ready() -> bool:
    # Re-resolve current configuration and probe remote health on every check.
    # Only each local scanner's warm-up is cached, never service availability.
    scanner = get_semantic_scanner()
    if scanner is None:
        return True
    scanner.warm()
    return True


def _file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _safe_model_text(text: str) -> str:
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
    return _bounded_model_text(redact_text(normalized) or "")


def _bounded_model_text(text: str) -> str:
    if len(text) <= MAX_MODEL_CHARACTERS:
        return text
    segment_length = (MAX_MODEL_CHARACTERS - 2) // 3
    middle_start = (len(text) - segment_length) // 2
    return "\n".join(
        (
            text[:segment_length],
            text[middle_start : middle_start + segment_length],
            text[-segment_length:],
        )
    )


def _select_rows(value: object, indices: list[int]) -> object:
    if isinstance(value, list):
        return [value[index] for index in indices]
    return value[indices]
