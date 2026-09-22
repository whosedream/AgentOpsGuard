"""Encrypted, expiring recovered tool results."""
import sqlalchemy as sa
from alembic import op

revision = "0019_recovered_tool_results"
down_revision = "0018_tool_receipt_contract"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tool_invocations", sa.Column("encrypted_result", sa.Text()))
    op.add_column("tool_invocations", sa.Column("result_expires_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("tool_invocations", "result_expires_at")
    op.drop_column("tool_invocations", "encrypted_result")
