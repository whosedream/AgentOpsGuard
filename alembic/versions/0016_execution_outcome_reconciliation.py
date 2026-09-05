"""add explicit execution outcome reconciliation evidence

Revision ID: 0016_execution_reconciliation
Revises: 0015_audit_append_only
Create Date: 2026-09-04
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "0016_execution_reconciliation"
down_revision: str | None = "0015_audit_append_only"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "execution_requests",
        sa.Column("reconciliation_resolution", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "execution_requests",
        sa.Column("reconciliation_evidence_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "execution_requests",
        sa.Column("reconciled_by", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "execution_requests",
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("execution_requests", "reconciled_at")
    op.drop_column("execution_requests", "reconciled_by")
    op.drop_column("execution_requests", "reconciliation_evidence_sha256")
    op.drop_column("execution_requests", "reconciliation_resolution")
