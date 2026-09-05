from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from agentops_guard.backend.models import AuditChainHead, AuditLog
from agentops_guard.backend.security.context import current_auth_context
from agentops_guard.backend.services.content import new_id, redact_secret_text, redact_value
from agentops_guard.backend.services.mcp_tool_revisions import canonical_json


_INTERNAL_AUDIT_ID_FIELDS = {"policy_decision_id", "retry_of"}
_INTERNAL_AUDIT_ID = re.compile(r"^[a-z][a-z0-9_]*_[0-9a-f]{24}$")


@dataclass(frozen=True)
class AuditIntegrity:
    valid: bool
    checked_entries: int
    broken_entry_id: str | None = None


def record_audit(
    db: Session,
    *,
    project_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    actor_type: str = "api_key",
    actor_id: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    auth = current_auth_context()
    resolved_actor_type = actor_type
    resolved_actor_id = actor_id
    if auth is not None and resolved_actor_id is None:
        resolved_actor_type = auth.kind
        resolved_actor_id = auth.actor_id
    resolved_actor_id = redact_secret_text(resolved_actor_id)
    resource_id = redact_secret_text(resource_id)
    before = redact_value(before)
    after = redact_value(after)
    metadata = _redact_audit_metadata(metadata or {})
    lock_audit_chain(db, project_id)
    head = (
        db.query(AuditChainHead)
        .filter(AuditChainHead.project_id == project_id)
        .with_for_update()
        .one_or_none()
    )
    row_id = new_id("audit")
    created_at = datetime.now(UTC)
    previous_hash = head.entry_hash if head is not None else None
    entry_hash = _audit_hash(
        previous_hash=previous_hash,
        row_id=row_id,
        project_id=project_id,
        actor_type=resolved_actor_type,
        actor_id=resolved_actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        before=before,
        after=after,
        metadata=metadata,
        created_at=created_at,
    )
    row = AuditLog(
        id=row_id,
        project_id=project_id,
        actor_type=resolved_actor_type,
        actor_id=resolved_actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        before=before,
        after=after,
        metadata_json=metadata,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        created_at=created_at,
    )
    db.add(row)
    if head is None:
        db.add(
            AuditChainHead(
                project_id=project_id,
                entry_hash=entry_hash,
                entry_id=row_id,
                updated_at=created_at,
            )
        )
    else:
        head.entry_hash = entry_hash
        head.entry_id = row_id
        head.updated_at = created_at
    db.flush()
    return row


def _redact_audit_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in metadata.items():
        safe_key = redact_value(key)
        if (
            key in _INTERNAL_AUDIT_ID_FIELDS
            and isinstance(value, str)
            and _INTERNAL_AUDIT_ID.fullmatch(value)
        ):
            redacted[safe_key] = value
        else:
            redacted[safe_key] = redact_value(value)
    return redacted


def verify_audit_chain(db: Session, project_id: str) -> AuditIntegrity:
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.project_id == project_id, AuditLog.entry_hash.is_not(None))
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        .all()
    )
    result = _verify_rows(rows)
    if not result.valid:
        return result
    previous_hash = rows[-1].entry_hash if rows else None
    head = db.get(AuditChainHead, project_id)
    if rows and (head is None or head.entry_hash != previous_hash or head.entry_id != rows[-1].id):
        return AuditIntegrity(False, len(rows), rows[-1].id)
    return AuditIntegrity(True, len(rows))


def verify_audit_prefix(
    db: Session,
    project_id: str,
    *,
    checked_entries: int,
    expected_entry_id: str,
    expected_entry_hash: str,
) -> AuditIntegrity:
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.project_id == project_id, AuditLog.entry_hash.is_not(None))
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        .limit(checked_entries)
        .all()
    )
    if len(rows) != checked_entries:
        return AuditIntegrity(False, len(rows), rows[-1].id if rows else None)
    result = _verify_rows(rows)
    if not result.valid:
        return result
    if not rows or rows[-1].id != expected_entry_id or rows[-1].entry_hash != expected_entry_hash:
        return AuditIntegrity(False, len(rows), rows[-1].id if rows else None)
    return AuditIntegrity(True, len(rows))


def _verify_rows(rows: list[AuditLog]) -> AuditIntegrity:
    previous_hash = None
    for index, row in enumerate(rows, start=1):
        if row.previous_hash != previous_hash:
            return AuditIntegrity(False, index, row.id)
        expected = _audit_hash(
            previous_hash=previous_hash,
            row_id=row.id,
            project_id=row.project_id,
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            before=row.before,
            after=row.after,
            metadata=row.metadata_json or {},
            created_at=row.created_at,
        )
        if row.entry_hash != expected:
            return AuditIntegrity(False, index, row.id)
        previous_hash = row.entry_hash
    return AuditIntegrity(True, len(rows))


def lock_audit_chain(db: Session, project_id: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:project_id))"),
            {"project_id": project_id},
        )


def _audit_hash(
    *,
    previous_hash: str | None,
    row_id: str,
    project_id: str,
    actor_type: str,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    metadata: dict[str, Any],
    created_at: object,
) -> str:
    normalized_created_at = created_at
    if normalized_created_at.tzinfo is None:
        normalized_created_at = normalized_created_at.replace(tzinfo=UTC)
    value = {
        "previous_hash": previous_hash,
        "id": row_id,
        "project_id": project_id,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "before": before,
        "after": after,
        "metadata": metadata,
        "created_at": normalized_created_at.isoformat(),
    }
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()
