from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from agentops_guard.backend.schemas import ComponentStatus


def migration_status(db: Session) -> ComponentStatus:
    try:
        inspector = inspect(db.bind)
        tables = set(inspector.get_table_names())
        dialect = db.bind.dialect.name if db.bind is not None else "unknown"
        if "alembic_version" not in tables:
            if dialect == "sqlite":
                return ComponentStatus(status="skipped", detail="alembic_version table is absent for local SQLite bootstrap")
            return ComponentStatus(status="error", detail="alembic_version table is missing")

        current = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        head = _alembic_head()
        if current == head:
            return ComponentStatus(status="ok", detail=f"head={head}")
        return ComponentStatus(status="error", detail=f"migration mismatch: current={current or 'none'} head={head}")
    except Exception as exc:
        return ComponentStatus(status="error", detail=str(exc))


def _alembic_head() -> str:
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)
    return script.get_current_head()
