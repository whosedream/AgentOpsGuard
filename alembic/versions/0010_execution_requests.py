"""add durable approval-bound execution requests

Revision ID: 0010_execution_requests
Revises: 0009_policy_snapshots
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0010_execution_requests"
down_revision: str | None = "0009_policy_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column("execution_request_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_approval_requests_execution_request_id",
        "approval_requests",
        ["execution_request_id"],
    )
    op.create_table(
        "execution_requests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("run_id", sa.String(64)),
        sa.Column("decision_id", sa.String(64), nullable=False),
        sa.Column("approval_id", sa.String(64), nullable=False),
        sa.Column("subject", sa.JSON(), nullable=False),
        sa.Column("actor_digest", sa.String(64), nullable=False),
        sa.Column("server_id", sa.String(64), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False),
        sa.Column("tool_revision_id", sa.String(64), nullable=False),
        sa.Column("tool_revision_digest", sa.String(64), nullable=False),
        sa.Column("arguments_digest", sa.String(64), nullable=False),
        sa.Column("intent_ref", sa.String(64)),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("policy_snapshot_digest", sa.String(64), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_labels", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(128)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("claimed_by", sa.String(128)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("approval_id", name="uq_execution_request_approval"),
        sa.UniqueConstraint(
            "project_id",
            "idempotency_key",
            name="uq_execution_request_idempotency",
        ),
    )
    for column in (
        "project_id",
        "run_id",
        "decision_id",
        "approval_id",
        "actor_digest",
        "server_id",
        "tool_name",
        "tool_revision_id",
        "arguments_digest",
        "status",
        "lease_expires_at",
        "expires_at",
    ):
        op.create_index(f"ix_execution_requests_{column}", "execution_requests", [column])


def downgrade() -> None:
    op.drop_table("execution_requests")
    op.drop_index(
        "ix_approval_requests_execution_request_id",
        table_name="approval_requests",
    )
    op.drop_column("approval_requests", "execution_request_id")
