"""service credentials

Revision ID: 0005_service_credentials
Revises: 0004_identity_rbac
Create Date: 2026-08-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0005_service_credentials"
down_revision: str | None = "0004_identity_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_credentials",
        sa.Column("credential_ref", sa.String(64), primary_key=True),
        sa.Column(
            "project_id",
            sa.String(64),
            sa.ForeignKey("projects.id"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("binding_ciphertext", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("tool", sa.String(128), nullable=False),
        sa.Column("origin", sa.String(255), nullable=False),
        sa.Column("injection_field", sa.String(64), nullable=False),
        sa.Column("credential_scope", sa.String(128), nullable=False),
        sa.Column("allowed_actor_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_service_credentials_project_id",
        "service_credentials",
        ["project_id"],
    )
    op.create_index(
        "ix_service_credentials_status", "service_credentials", ["status"]
    )


def downgrade() -> None:
    op.drop_index("ix_service_credentials_status", table_name="service_credentials")
    op.drop_index(
        "ix_service_credentials_project_id", table_name="service_credentials"
    )
    op.drop_table("service_credentials")
