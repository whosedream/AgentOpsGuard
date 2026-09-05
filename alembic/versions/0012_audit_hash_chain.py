"""add per-project audit hash chains

Revision ID: 0012_audit_hash_chain
Revises: 0011_transactional_outbox
Create Date: 2026-09-04
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
import unicodedata
from typing import Any

from alembic import op
import rfc8785
import sqlalchemy as sa


revision: str = "0012_audit_hash_chain"
down_revision: str | None = "0011_transactional_outbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("previous_hash", sa.String(64)))
    op.add_column("audit_logs", sa.Column("entry_hash", sa.String(64)))
    op.create_index("ix_audit_logs_entry_hash", "audit_logs", ["entry_hash"])
    op.create_table(
        "audit_chain_heads",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.Column("entry_id", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    _backfill_audit_chain()


def downgrade() -> None:
    op.drop_table("audit_chain_heads")
    op.drop_index("ix_audit_logs_entry_hash", table_name="audit_logs")
    op.drop_column("audit_logs", "entry_hash")
    op.drop_column("audit_logs", "previous_hash")


def _backfill_audit_chain() -> None:
    audit_logs = sa.table(
        "audit_logs",
        sa.column("id", sa.String(64)),
        sa.column("project_id", sa.String(64)),
        sa.column("actor_type", sa.String(64)),
        sa.column("actor_id", sa.String(128)),
        sa.column("action", sa.String(128)),
        sa.column("resource_type", sa.String(128)),
        sa.column("resource_id", sa.String(128)),
        sa.column("before", sa.JSON()),
        sa.column("after", sa.JSON()),
        sa.column("metadata_json", sa.JSON()),
        sa.column("previous_hash", sa.String(64)),
        sa.column("entry_hash", sa.String(64)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    chain_heads = sa.table(
        "audit_chain_heads",
        sa.column("project_id", sa.String(64)),
        sa.column("entry_hash", sa.String(64)),
        sa.column("entry_id", sa.String(64)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(audit_logs).order_by(
            audit_logs.c.project_id.asc(),
            audit_logs.c.created_at.asc(),
            audit_logs.c.id.asc(),
        )
    ).mappings().all()
    previous_by_project: dict[str, str | None] = {}
    latest_by_project: dict[str, tuple[str, str, datetime]] = {}
    for row in rows:
        project_id = str(row["project_id"])
        previous_hash = previous_by_project.get(project_id)
        created_at = _as_datetime(row["created_at"])
        entry_hash = _legacy_audit_hash(row, previous_hash, created_at)
        connection.execute(
            audit_logs.update()
            .where(audit_logs.c.id == row["id"])
            .values(previous_hash=previous_hash, entry_hash=entry_hash)
        )
        previous_by_project[project_id] = entry_hash
        latest_by_project[project_id] = (str(row["id"]), entry_hash, created_at)
    for project_id, (entry_id, entry_hash, updated_at) in latest_by_project.items():
        connection.execute(
            chain_heads.insert().values(
                project_id=project_id,
                entry_hash=entry_hash,
                entry_id=entry_id,
                updated_at=updated_at,
            )
        )


def _legacy_audit_hash(
    row: Mapping[str, Any],
    previous_hash: str | None,
    created_at: datetime,
) -> str:
    payload = {
        "previous_hash": previous_hash,
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "actor_type": str(row["actor_type"]),
        "actor_id": row["actor_id"],
        "action": str(row["action"]),
        "resource_type": str(row["resource_type"]),
        "resource_id": row["resource_id"],
        "before": row["before"],
        "after": row["after"],
        "metadata": row["metadata_json"] or {},
        "created_at": created_at.isoformat(),
    }
    normalized = _normalize_strings(payload)
    return sha256(rfc8785.dumps(normalized)).hexdigest()


def _as_datetime(value: object) -> datetime:
    resolved = datetime.fromisoformat(value) if isinstance(value, str) else value
    if not isinstance(resolved, datetime):
        raise TypeError("audit created_at must be a timestamp")
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=UTC)
    return resolved.astimezone(UTC)


def _normalize_strings(value: object) -> object:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {_normalize_strings(key): _normalize_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_strings(item) for item in value]
    return value
