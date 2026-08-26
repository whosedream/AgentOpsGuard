"""track MCP runtime provider

Revision ID: 0006_mcp_runtime_provider
Revises: 0005_service_credentials
Create Date: 2026-08-24
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0006_mcp_runtime_provider"
down_revision: str | None = "0005_service_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column(
            "runtime_provider",
            sa.String(32),
            nullable=False,
            server_default="direct",
        ),
    )


def downgrade() -> None:
    op.drop_column("mcp_servers", "runtime_provider")
