"""add background job leases

Revision ID: 0013_background_job_leases
Revises: 0012_audit_hash_chain
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0013_background_job_leases"
down_revision: str | None = "0012_audit_hash_chain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "background_jobs",
        sa.Column("lease_owner", sa.String(128)),
    )
    op.add_column(
        "background_jobs",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_background_jobs_lease_owner",
        "background_jobs",
        ["lease_owner"],
    )
    op.create_index(
        "ix_background_jobs_lease_expires_at",
        "background_jobs",
        ["lease_expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_background_jobs_lease_expires_at",
        table_name="background_jobs",
    )
    op.drop_index(
        "ix_background_jobs_lease_owner",
        table_name="background_jobs",
    )
    op.drop_column("background_jobs", "lease_expires_at")
    op.drop_column("background_jobs", "lease_owner")
