"""make PostgreSQL audit history append-only

Revision ID: 0015_audit_append_only
Revises: 0014_audit_checkpoints
Create Date: 2026-09-04
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0015_audit_append_only"
down_revision: str | None = "0014_audit_checkpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLES = ("audit_logs", "audit_checkpoints")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE FUNCTION agentops_reject_audit_history_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            RAISE EXCEPTION 'immutable audit history: % on % is forbidden', TG_OP, TG_TABLE_NAME
                USING ERRCODE = '55000';
            RETURN NULL;
        END;
        $function$
        """
    )
    for table in _TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {table}_reject_update_delete
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION agentops_reject_audit_history_mutation()
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER {table}_reject_truncate
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION agentops_reject_audit_history_mutation()
            """
        )
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_reject_update_delete")
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_reject_truncate")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in reversed(_TABLES):
        op.execute(f"DROP TRIGGER {table}_reject_truncate ON {table}")
        op.execute(f"DROP TRIGGER {table}_reject_update_delete ON {table}")
    op.execute("DROP FUNCTION agentops_reject_audit_history_mutation()")
