from collections.abc import Generator
from datetime import UTC, datetime
from threading import Lock

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from agentops_guard.backend.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
_bootstrap_lock = Lock()
_bootstrapped = False


def utcnow() -> datetime:
    return datetime.now(UTC)


def get_db() -> Generator[Session, None, None]:
    ensure_schema()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    ensure_schema(force=True)


def ensure_schema(force: bool = False) -> None:
    global _bootstrapped
    if _bootstrapped and not force:
        return
    with _bootstrap_lock:
        if _bootstrapped and not force:
            return
        _create_schema()
        _bootstrapped = True


def _create_schema() -> None:
    from agentops_guard.backend import models  # noqa: F401

    if settings.database_url.startswith("postgres"):
        with engine.begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(4242424242)"))
            Base.metadata.create_all(bind=connection)
            _ensure_project_columns(connection)
        return

    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        _ensure_project_columns(connection)


def _ensure_project_columns(connection) -> None:
    inspector = inspect(connection)
    if "projects" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("projects")}
    dialect = connection.dialect.name
    if "policy_fail_mode" not in columns:
        connection.execute(text("ALTER TABLE projects ADD COLUMN policy_fail_mode VARCHAR(64) DEFAULT 'closed_for_high_risk'"))
    if "status" not in columns:
        connection.execute(text("ALTER TABLE projects ADD COLUMN status VARCHAR(32) DEFAULT 'active'"))
    if "metadata_json" not in columns:
        json_type = "JSONB" if dialect == "postgresql" else "JSON"
        default_value = "'{}'::jsonb" if dialect == "postgresql" else "'{}'"
        connection.execute(text(f"ALTER TABLE projects ADD COLUMN metadata_json {json_type} DEFAULT {default_value}"))
