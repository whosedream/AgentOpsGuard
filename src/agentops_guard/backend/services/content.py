import hashlib
import re
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import ContentObject, Project
from agentops_guard.backend.schemas import ContentIn

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    (
        "ssh_private_key",
        re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"
        ),
    ),
    ("db_url", re.compile(r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+", re.IGNORECASE)),
    (
        "bearer_token",
        re.compile(
            r"\bBearer\s+(?=[A-Za-z0-9._~+/=-]{12,}(?:[\s,;]|$))"
            r"(?=[^\s,;]*[0-9._~+/-])[A-Za-z0-9._~+/-]+=*",
            re.IGNORECASE,
        ),
    ),
    (
        "url_userinfo",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@", re.IGNORECASE),
    ),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("phone", re.compile(r"(?<!\d)(?:\+?\d{1,3}[- ]?)?\d{3}[- ]?\d{3,4}[- ]?\d{4}(?!\d)")),
]


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def summarize_text(text: str | None, limit: int = 240) -> str | None:
    if not text:
        return None
    compact = " ".join(text.split())
    return compact[:limit] + ("…" if len(compact) > limit else "")


def detect_secret_labels(text: str | None) -> list[str]:
    if not text:
        return []
    labels = []
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            labels.append(label)
    return labels


def redact_text(text: str | None) -> str | None:
    if text is None:
        return None
    redacted = text
    for label, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{label}]", redacted)
    return redacted


def redact_secret_text(text: str | None) -> str | None:
    if text is None:
        return None
    redacted = text
    for label, pattern in SECRET_PATTERNS:
        if label in {"email", "phone"}:
            continue
        redacted = pattern.sub(f"[REDACTED:{label}]", redacted)
    return redacted


def redact_value(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            redact_text(key) if isinstance(key, str) else key: redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def redact_structured_value(value: Any) -> Any:
    """Redact string values while preserving keys and JSON-compatible value types."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_structured_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_structured_value(item) for item in value]
    return value


def merge_labels(*groups: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for group in groups:
        for label in group:
            if label not in seen:
                seen.add(label)
                result.append(label)
    return result


def persist_content(db: Session, project_id: str, content: ContentIn | None) -> str | None:
    if content is None or content.text is None:
        return None
    settings = get_settings()
    project = db.get(Project, project_id)
    redacted = redact_text(content.text)
    secret_labels = detect_secret_labels(content.text)
    labels = merge_labels(content.labels, secret_labels)
    default_store_raw = (
        project.store_raw_content if project is not None else settings.store_raw_content
    )
    store_raw = default_store_raw if content.store_raw is None else content.store_raw
    content_object = ContentObject(
        id=new_id("content"),
        project_id=project_id,
        content_hash=hash_text(content.text),
        content_type=content.content_type,
        summary=summarize_text(redacted),
        redacted_text=redacted,
        raw_text=content.text if store_raw and not secret_labels else None,
        labels=labels,
        metadata_json=redact_value(content.metadata),
    )
    db.add(content_object)
    db.flush()
    return content_object.id
