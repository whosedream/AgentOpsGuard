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
                connection.execute(text("ALTER TABLE projects ADD COLUMN organization_id VARCHAR(64) DEFAULT ''"))
        if "policy_packs" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("policy_packs")}
            if "family_id" not in columns:
                connection.execute(text("ALTER TABLE policy_packs ADD COLUMN family_id VARCHAR(64) DEFAULT ''"))
        if "sessions" in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns("sessions")}
            if "token_hash" not in columns:
                connection.execute(text("ALTER TABLE sessions ADD COLUMN token_hash VARCHAR(128) DEFAULT ''"))
