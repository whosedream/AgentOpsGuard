"""persist policy decision snapshots

Revision ID: 0009_policy_snapshots
Revises: 0008_mcp_tool_revisions
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0009_policy_snapshots"
down_revision: str | None = "0008_mcp_tool_revisions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "policy_decisions",
        sa.Column(
            "builtin_policy_version",
            sa.String(64),
            nullable=False,
            server_default="legacy",
        ),
    )
    op.add_column(
        "policy_decisions",
        sa.Column(
            "policy_pack_revisions",
            sa.JSON(),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        "policy_decisions",
        sa.Column("opa_bundle_revision", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("policy_decisions", "opa_bundle_revision")
    op.drop_column("policy_decisions", "policy_pack_revisions")
    op.drop_column("policy_decisions", "builtin_policy_version")
