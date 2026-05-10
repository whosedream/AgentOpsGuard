"""policy pack revisions

Revision ID: 0003_policy_pack_revisions
Revises: 0002_control_plane
Create Date: 2026-05-10
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0003_policy_pack_revisions"
down_revision: str | None = "0002_control_plane"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("policy_packs") as batch:
        batch.add_column(sa.Column("family_id", sa.String(64), server_default="legacy"))
    op.create_index("ix_policy_packs_family_id", "policy_packs", ["family_id"])
    op.execute("UPDATE policy_packs SET family_id = id WHERE family_id = 'legacy'")


def downgrade() -> None:
    op.drop_index("ix_policy_packs_family_id", table_name="policy_packs")
    with op.batch_alter_table("policy_packs") as batch:
        batch.drop_column("family_id")
