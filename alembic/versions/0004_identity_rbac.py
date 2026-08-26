"""identity and rbac

Revision ID: 0004_identity_rbac
Revises: 0003_policy_pack_revisions
Create Date: 2026-05-12
"""

from collections.abc import Sequence
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision: str = "0004_identity_rbac"
down_revision: str | None = "0003_policy_pack_revisions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("auth_provider", sa.String(64), nullable=False),
        sa.Column("external_subject", sa.String(255)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_status", "users", ["status"])

    op.create_table(
        "memberships",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("organization_id", sa.String(64), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_memberships_organization_id", "memberships", ["organization_id"])
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_role", "memberships", ["role"])
    op.create_index("ix_memberships_status", "memberships", ["status"])
    op.create_index("ix_memberships_org_user", "memberships", ["organization_id", "user_id"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("organization_id", sa.String(64), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("membership_id", sa.String(64), sa.ForeignKey("memberships.id"), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)
    op.create_index("ix_sessions_organization_id", "sessions", ["organization_id"])
    op.create_index("ix_sessions_membership_id", "sessions", ["membership_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_index("ix_sessions_revoked_at", "sessions", ["revoked_at"])
    op.create_index("ix_sessions_user_org", "sessions", ["user_id", "organization_id"])

    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("organization_id", sa.String(64), server_default=""))
    op.create_index("ix_projects_organization_id", "projects", ["organization_id"])

    bootstrap_org_id = "org_bootstrap"
    timestamp = datetime.now(timezone.utc)
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "INSERT INTO organizations (id, slug, name, created_at) VALUES (:id, :slug, :name, :created_at)"
        ),
        {
            "id": bootstrap_org_id,
            "slug": "bootstrap",
            "name": "Bootstrap Organization",
            "created_at": timestamp,
        },
    )
    bind.execute(sa.text("UPDATE projects SET organization_id = :org_id WHERE organization_id = ''"), {"org_id": bootstrap_org_id})


def downgrade() -> None:
    op.drop_index("ix_projects_organization_id", table_name="projects")
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("organization_id")

    for index in [
        "ix_sessions_user_org",
        "ix_sessions_revoked_at",
        "ix_sessions_expires_at",
        "ix_sessions_membership_id",
        "ix_sessions_organization_id",
        "ix_sessions_token_hash",
        "ix_sessions_user_id",
    ]:
        op.drop_index(index, table_name="sessions")
    op.drop_table("sessions")

    for index in [
        "ix_memberships_org_user",
        "ix_memberships_status",
        "ix_memberships_role",
        "ix_memberships_user_id",
        "ix_memberships_organization_id",
    ]:
        op.drop_index(index, table_name="memberships")
    op.drop_table("memberships")

    op.drop_index("ix_users_status", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")
