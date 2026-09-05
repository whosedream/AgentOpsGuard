"""bind API keys to trusted agent identities

Revision ID: 0007_gateway_identity
Revises: 0006_mcp_runtime_provider
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0007_gateway_identity"
down_revision: str | None = "0006_mcp_runtime_provider"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("agent_id", sa.String(128), nullable=True))
    op.create_index("ix_api_keys_agent_id", "api_keys", ["agent_id"])


def downgrade() -> None:
    op.drop_index("ix_api_keys_agent_id", table_name="api_keys")
    op.drop_column("api_keys", "agent_id")
