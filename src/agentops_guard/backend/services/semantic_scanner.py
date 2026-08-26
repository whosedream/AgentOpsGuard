from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable
from functools import cached_property, lru_cache
from pathlib import Path
from threading import Lock
from typing import Protocol

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.schemas import ScanRequest, SemanticAssessment
from agentops_guard.backend.services.content import redact_text


SEMANTIC_MODEL_ID = (
    "patronus-studio/wolf-defender-prompt-injection-small@"
    "eff31df5c97ca127b7b55da255a160f88a625c97"
)
SEMANTIC_MANIFEST_SHA256 = "06bcefdafa24f95cd9901d8a46ec0f295ac144e89c9618197733948987c3bec4"
MAX_MODEL_CHARACTERS = 512
MAX_MODEL_WINDOWS = 2
MODEL_BATCH_SIZE = 1
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
    pass


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

    def predict(self, text: str) -> float:
        if not self._inference_lock.acquire(blocking=False):
            raise SemanticScannerUnavailable("semantic model is busy")
        try:
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
        finally:
            self._inference_lock.release()


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

    @cached_property
    def backend(self) -> SemanticBackend:
        return self._backend_factory(self.model_path)

    def assess(self, request: ScanRequest) -> SemanticAssessment | None:
        if request.source not in SEMANTIC_SOURCES:
            return None
        normalized = unicodedata.normalize("NFKC", request.content)
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
        safe_text = redact_text(normalized) or ""
        try:
            score = self.backend.predict(safe_text)
        except (OSError, RuntimeError, ValueError) as exc:
            raise SemanticScannerUnavailable("semantic model inference failed") from exc
        return SemanticAssessment(
            status="ok",
            mode=self.mode,
            label="prompt_injection" if score >= self.threshold else "benign",
            score=score,
            model=SEMANTIC_MODEL_ID,
        )

    def warm(self) -> None:
        self.backend.predict("health check")


def get_semantic_scanner() -> SemanticScanner | None:
    settings = get_settings()
    if settings.semantic_scanner_mode == "disabled":
        return None
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
def semantic_scanner_ready() -> bool:
    scanner = get_semantic_scanner()
    if scanner is None:
        return True
    scanner.warm()
    return True


def _file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _bounded_model_text(text: str) -> str:
    if len(text) <= MAX_MODEL_CHARACTERS:
        return text
    segment_length = MAX_MODEL_CHARACTERS // 3
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
