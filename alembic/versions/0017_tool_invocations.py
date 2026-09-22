"""Durable tool receipts and operator-reviewed queue capability."""

import sqlalchemy as sa
from alembic import op

revision = "0017_tool_invocations"
down_revision = "0016_execution_reconciliation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tool_execution_policies",
        sa.Column("tool_id", sa.String(384), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("revision_digest", sa.String(64), nullable=False),
        sa.Column("queue_enabled", sa.Boolean(), nullable=False),
        sa.Column("retry_mode", sa.String(32), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("updated_by", sa.String(128), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_tool_execution_policies_project_id", "tool_execution_policies", ["project_id"]
    )
    op.create_table(
        "tool_invocations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("actor_digest", sa.String(64), nullable=False),
        sa.Column("subject", sa.JSON(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("tool_id", sa.String(384), nullable=False),
        sa.Column("revision_digest", sa.String(64)),
        sa.Column("execution_policy_digest", sa.String(64)),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("encrypted_payload", sa.Text()),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("job_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "project_id", "actor_digest", "request_id", name="uq_tool_invocation_request"
        ),
    )
    op.create_index("ix_tool_invocations_project_id", "tool_invocations", ["project_id"])
    op.create_index("ix_tool_invocations_status", "tool_invocations", ["status"])


def downgrade() -> None:
    op.drop_table("tool_invocations")
    op.drop_table("tool_execution_policies")
