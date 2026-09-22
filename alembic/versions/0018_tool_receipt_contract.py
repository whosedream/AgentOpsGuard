"""Reviewed downstream receipt contract and immutable dispatch binding."""

import sqlalchemy as sa
from alembic import op

revision = "0018_tool_receipt_contract"
down_revision = "0017_tool_invocations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tool_execution_policies", sa.Column("receipt_contract", sa.JSON()))
    op.add_column("tool_invocations", sa.Column("receipt_binding", sa.JSON()))


def downgrade() -> None:
    op.drop_column("tool_invocations", "receipt_binding")
    op.drop_column("tool_execution_policies", "receipt_contract")
