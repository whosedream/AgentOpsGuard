"""add signed audit checkpoints

Revision ID: 0014_audit_checkpoints
Revises: 0013_background_job_leases
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0014_audit_checkpoints"
down_revision: str | None = "0013_background_job_leases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("entry_id", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.Column("checked_entries", sa.Integer(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("signer", sa.String(64), nullable=False),
        sa.Column("key_name", sa.String(255), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_checkpoints_project_id", "audit_checkpoints", ["project_id"])
    op.create_index("ix_audit_checkpoints_entry_id", "audit_checkpoints", ["entry_id"])
    op.create_index("ix_audit_checkpoints_entry_hash", "audit_checkpoints", ["entry_hash"])
    op.create_index(
        "ix_audit_checkpoints_payload_digest",
        "audit_checkpoints",
        ["payload_digest"],
        unique=True,
    )
    op.create_index("ix_audit_checkpoints_issued_at", "audit_checkpoints", ["issued_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_checkpoints_issued_at", table_name="audit_checkpoints")
    op.drop_index("ix_audit_checkpoints_payload_digest", table_name="audit_checkpoints")
    op.drop_index("ix_audit_checkpoints_entry_hash", table_name="audit_checkpoints")
    op.drop_index("ix_audit_checkpoints_entry_id", table_name="audit_checkpoints")
    op.drop_index("ix_audit_checkpoints_project_id", table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
