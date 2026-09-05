from collections.abc import Generator
from datetime import UTC, datetime
from threading import Lock

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.services.migrations import migration_status


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
_bootstrap_lock = Lock()
_schema_initialized = False


def utcnow() -> datetime:
    return datetime.now(UTC)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    ensure_schema(force=True)


def ensure_schema(force: bool = False) -> None:
    global _schema_initialized
    if _schema_initialized and not force:
        return
    with _bootstrap_lock:
        if _schema_initialized and not force:
            return
        _initialize_or_validate_schema()
        _schema_initialized = True


def _initialize_or_validate_schema() -> None:
    from agentops_guard.backend import models  # noqa: F401

    runtime_settings = get_settings()
    if _should_bootstrap_schema(runtime_settings):
        Base.metadata.create_all(bind=engine)
        _apply_dev_bootstrap_fixes()
        return

    db = SessionLocal()
    try:
        status = migration_status(db)
    finally:
        db.close()
    if status.status == "ok":
        return
    raise RuntimeError(f"database schema is not ready: {status.detail or status.status}")


def _should_bootstrap_schema(runtime_settings) -> bool:
    return (
        runtime_settings.env == "dev"
        and runtime_settings.allow_schema_bootstrap
        and runtime_settings.database_url.startswith("sqlite")
    )


def _apply_dev_bootstrap_fixes() -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        if "projects" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("projects")}
            if "organization_id" not in columns:
                connection.execute(
                    text("ALTER TABLE projects ADD COLUMN organization_id VARCHAR(64) DEFAULT ''")
                )
        if "policy_packs" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("policy_packs")}
            if "family_id" not in columns:
                connection.execute(
                    text("ALTER TABLE policy_packs ADD COLUMN family_id VARCHAR(64) DEFAULT ''")
                )
        if "policy_decisions" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("policy_decisions")}
            if "builtin_policy_version" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE policy_decisions ADD COLUMN "
                        "builtin_policy_version VARCHAR(64) DEFAULT 'legacy'"
                    )
                )
            if "policy_pack_revisions" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE policy_decisions ADD COLUMN "
                        "policy_pack_revisions JSON DEFAULT '[]'"
                    )
                )
            if "opa_bundle_revision" not in columns:
                connection.execute(
                    text("ALTER TABLE policy_decisions ADD COLUMN opa_bundle_revision VARCHAR(128)")
                )
        if "sessions" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("sessions")}
            if "token_hash" not in columns:
                connection.execute(
                    text("ALTER TABLE sessions ADD COLUMN token_hash VARCHAR(128) DEFAULT ''")
                )
        if "mcp_servers" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("mcp_servers")}
            if "runtime_provider" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE mcp_servers ADD COLUMN runtime_provider "
                        "VARCHAR(32) DEFAULT 'direct'"
                    )
                )
        if "mcp_tools" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("mcp_tools")}
            if "current_revision_id" not in columns:
                connection.execute(
                    text("ALTER TABLE mcp_tools ADD COLUMN current_revision_id VARCHAR(64)")
                )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_mcp_tools_current_revision_id "
                    "ON mcp_tools (current_revision_id)"
                )
            )
        if "api_keys" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("api_keys")}
            if "agent_id" not in columns:
                connection.execute(text("ALTER TABLE api_keys ADD COLUMN agent_id VARCHAR(128)"))
            connection.execute(
                text("CREATE INDEX IF NOT EXISTS ix_api_keys_agent_id ON api_keys (agent_id)")
            )
        if "mcp_tool_revisions" in inspector.get_table_names():
            connection.execute(
                text(
                    "CREATE TRIGGER IF NOT EXISTS mcp_tool_revisions_no_update "
                    "BEFORE UPDATE ON mcp_tool_revisions BEGIN "
                    "SELECT RAISE(ABORT, 'MCP tool revisions are immutable'); END"
                )
            )
            connection.execute(
                text(
                    "CREATE TRIGGER IF NOT EXISTS mcp_tool_revisions_no_delete "
                    "BEFORE DELETE ON mcp_tool_revisions BEGIN "
                    "SELECT RAISE(ABORT, 'MCP tool revisions are immutable'); END"
                )
            )
        if "approval_requests" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("approval_requests")}
            if "execution_request_id" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE approval_requests ADD COLUMN execution_request_id VARCHAR(64)"
                    )
                )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_approval_requests_execution_request_id "
                    "ON approval_requests (execution_request_id)"
                )
            )
        if "audit_logs" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("audit_logs")}
            if "previous_hash" not in columns:
                connection.execute(
                    text("ALTER TABLE audit_logs ADD COLUMN previous_hash VARCHAR(64)")
                )
            if "entry_hash" not in columns:
                connection.execute(text("ALTER TABLE audit_logs ADD COLUMN entry_hash VARCHAR(64)"))
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_audit_logs_entry_hash ON audit_logs (entry_hash)"
                )
            )
        if "execution_requests" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("execution_requests")}
            if "lease_expires_at" not in columns:
                connection.execute(
                    text("ALTER TABLE execution_requests ADD COLUMN lease_expires_at DATETIME")
                )
            for name, column_type in (
                ("reconciliation_resolution", "VARCHAR(32)"),
                ("reconciliation_evidence_sha256", "VARCHAR(64)"),
                ("reconciled_by", "VARCHAR(128)"),
                ("reconciled_at", "DATETIME"),
            ):
                if name not in columns:
                    connection.execute(
                        text(f"ALTER TABLE execution_requests ADD COLUMN {name} {column_type}")
                    )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_execution_requests_lease_expires_at "
                    "ON execution_requests (lease_expires_at)"
                )
            )
        if "background_jobs" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("background_jobs")}
            if "lease_owner" not in columns:
                connection.execute(
                    text("ALTER TABLE background_jobs ADD COLUMN lease_owner VARCHAR(128)")
                )
            if "lease_expires_at" not in columns:
                connection.execute(
                    text("ALTER TABLE background_jobs ADD COLUMN lease_expires_at DATETIME")
                )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_background_jobs_lease_owner "
                    "ON background_jobs (lease_owner)"
                )
            )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_background_jobs_lease_expires_at "
                    "ON background_jobs (lease_expires_at)"
                )
            )
