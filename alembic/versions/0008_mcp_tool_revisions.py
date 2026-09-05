"""add immutable MCP tool revisions

Revision ID: 0008_mcp_tool_revisions
Revises: 0007_gateway_identity
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0008_mcp_tool_revisions"
down_revision: str | None = "0007_gateway_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("mcp_tools", sa.Column("current_revision_id", sa.String(64), nullable=True))
    op.create_index(
        "ix_mcp_tools_current_revision_id",
        "mcp_tools",
        ["current_revision_id"],
    )
    op.create_table(
        "mcp_tool_revisions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("tool_id", sa.String(128), nullable=False),
        sa.Column("server_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("source_digest", sa.String(64), nullable=False),
        sa.Column("server_digest", sa.String(64), nullable=False),
        sa.Column("descriptor", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_labels", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("scanner_version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tool_id", "content_digest", name="uq_mcp_tool_revision_digest"),
    )
    for column in ("project_id", "tool_id", "server_id", "name", "content_digest", "status"):
        op.create_index(f"ix_mcp_tool_revisions_{column}", "mcp_tool_revisions", [column])
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER mcp_tool_revisions_no_update "
            "BEFORE UPDATE ON mcp_tool_revisions BEGIN "
            "SELECT RAISE(ABORT, 'MCP tool revisions are immutable'); END"
        )
        op.execute(
            "CREATE TRIGGER mcp_tool_revisions_no_delete "
            "BEFORE DELETE ON mcp_tool_revisions BEGIN "
            "SELECT RAISE(ABORT, 'MCP tool revisions are immutable'); END"
        )
    elif dialect == "postgresql":
        op.execute(
            "CREATE FUNCTION reject_mcp_tool_revision_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
            "'MCP tool revisions are immutable'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER mcp_tool_revisions_no_mutation "
            "BEFORE UPDATE OR DELETE ON mcp_tool_revisions "
            "FOR EACH ROW EXECUTE FUNCTION reject_mcp_tool_revision_mutation()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS mcp_tool_revisions_no_update")
        op.execute("DROP TRIGGER IF EXISTS mcp_tool_revisions_no_delete")
    elif dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS mcp_tool_revisions_no_mutation ON mcp_tool_revisions")
        op.execute("DROP FUNCTION IF EXISTS reject_mcp_tool_revision_mutation()")
    op.drop_table("mcp_tool_revisions")
    op.drop_index("ix_mcp_tools_current_revision_id", table_name="mcp_tools")
    op.drop_column("mcp_tools", "current_revision_id")
