from __future__ import annotations

from hashlib import sha256
import unicodedata
from typing import Any

import rfc8785
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from agentops_guard.backend.models import McpServer, McpTool, McpToolRevision


SCANNER_VERSION = "agentops-scanner-v1"


def canonical_json(value: Any) -> str:
    normalized = _normalize_strings(value)
    return rfc8785.dumps(normalized).decode("utf-8")


def content_digest(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def record_tool_revision(
    db: Session,
    server: McpServer,
    tool: McpTool,
    *,
    source: dict[str, Any] | None = None,
    source_digest: str | None = None,
) -> McpToolRevision:
    descriptor = {
        "name": tool.name,
        "description": tool.description or "",
        "inputSchema": tool.input_schema or {},
        "annotations": tool.annotations or {},
    }
    if source is not None and isinstance(source.get("outputSchema"), dict):
        descriptor["outputSchema"] = source["outputSchema"]
    source_value = source if source is not None else descriptor
    server_value = {
        "id": server.id,
        "transport": server.transport,
        "runtime_provider": server.runtime_provider,
        "command": server.command,
        "args": server.args or [],
        "url": server.url,
        "trust_level": server.trust_level,
        "allowed_agents": server.allowed_agents or [],
    }
    revision_value = {
        "descriptor": descriptor,
        "source_digest": source_digest or content_digest(source_value),
        "server_digest": content_digest(server_value),
        "risk_score": tool.risk_score,
        "risk_labels": tool.risk_labels or [],
        "status": tool.status,
        "scanner_version": SCANNER_VERSION,
    }
    digest = content_digest(revision_value)
    revisions = (
        db.query(McpToolRevision)
        .filter(
            McpToolRevision.tool_id == tool.id,
            McpToolRevision.content_digest == digest,
        )
    )
    existing = revisions.one_or_none()
    if existing is None:
        dialect = db.get_bind().dialect.name
        if dialect not in {"postgresql", "sqlite"}:
            raise ValueError("tool revision storage supports PostgreSQL and SQLite")
        insert = postgresql_insert if dialect == "postgresql" else sqlite_insert
        statement = insert(McpToolRevision).values(
            id=f"toolrev_{digest[:48]}",
            project_id=tool.project_id,
            tool_id=tool.id,
            server_id=server.id,
            name=tool.name,
            content_digest=digest,
            source_digest=revision_value["source_digest"],
            server_digest=revision_value["server_digest"],
            descriptor=descriptor,
            risk_score=tool.risk_score,
            risk_labels=tool.risk_labels or [],
            status=tool.status,
            scanner_version=SCANNER_VERSION,
        )
        # Another gateway may publish this revision after our SELECT. Only the
        # same primary-key conflict is harmless: never update an immutable row
        # or roll back the caller's policy/audit transaction. DML also preserves
        # rollback semantics with SQLite's legacy transaction control.
        db.execute(statement.on_conflict_do_nothing(index_elements=["id"]))
        existing = revisions.one()  # Reject an ID collision with a different tool/digest.
    tool.current_revision_id = existing.id
    return existing


def _normalize_strings(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {_normalize_strings(key): _normalize_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_strings(item) for item in value]
    return value
