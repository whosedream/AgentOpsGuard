"""Bound PostgreSQL waits and retire demoted connections; never replay transactions."""
from contextlib import contextmanager

from fastapi import HTTPException
import psycopg
from sqlalchemy import create_engine, event, exc, text
from sqlalchemy.engine import make_url

from agentops_guard.backend.config import Settings


_FAILOVER_CODES = frozenset({"25006", "57P01", "57P02", "57P03"})
_UNAVAILABLE_CODES = _FAILOVER_CODES | {"53300", "57014", "55P03"}


class PostToolDatabaseUnavailable(HTTPException):
    """A tool was dispatched; its output is withheld, never silently replayed."""

    def __init__(self, tool_execution: dict):
        super().__init__(503, {"code": "post_tool_database_unavailable",
                              "tool_execution": tool_execution})


def database_unavailable(error: Exception) -> bool:
    if isinstance(error, exc.TimeoutError):
        return True
    if not isinstance(error, exc.DBAPIError):
        return False
    code = getattr(error.orig, "sqlstate", None)
    return bool(error.connection_invalidated or code in _UNAVAILABLE_CODES
                or (code and code.startswith("08"))
                or isinstance(error.orig, psycopg.OperationalError))


@contextmanager
def database_http_boundary(*, tool_execution: dict | None = None):
    try:
        yield
    except (exc.DBAPIError, exc.TimeoutError) as error:
        if not database_unavailable(error):
            raise
        # A 503 does not mean that an already-dispatched external action stopped.
        # Do not attach Retry-After or transparently replay the transaction/tool.
        if tool_execution is not None:
            raise PostToolDatabaseUnavailable(tool_execution) from None
        raise HTTPException(503, "Database temporarily unavailable") from None


def _require_writable(connection, _record, _proxy):
    previous = connection.autocommit
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only') = 'off'")
            writable = cursor.fetchone()[0]
    except psycopg.Error:
        # Pool retries here occur before the caller has a transaction or action.
        raise exc.DisconnectionError("Database primary connection unavailable") from None
    finally:
        if not connection.closed:
            connection.autocommit = previous
    if not writable:
        # A role change applies to other idle connections to that primary too.
        # Retire the old pool generation on next checkout, not one stale peer
        # per request. SQLAlchemy leaves checked-out transactions untouched;
        # this is connection acquisition recovery, never transaction replay.
        raise exc.InvalidatePoolError("Database connection is no longer writable")


def _invalidate_demoted_connection(context):
    code = getattr(context.original_exception, "sqlstate", None)
    if code in _FAILOVER_CODES:
        context.is_disconnect = True
        context.invalidate_pool_on_disconnect = True


def create_database_engine(settings: Settings, **overrides):
    url = make_url(settings.database_url)
    if url.get_backend_name() != "postgresql":
        args = {"check_same_thread": False} if url.get_backend_name() == "sqlite" else {}
        return create_engine(url, connect_args=args, future=True, **overrides)
    # Preserve operator options (e.g. search_path), but bounded waits cannot be
    # accidentally disabled by an older connection-string option.
    options = " ".join(filter(None, [url.query.get("options"),
        f"-c statement_timeout={settings.database_statement_timeout_ms}",
        f"-c lock_timeout={settings.database_lock_timeout_ms}"]))
    engine = create_engine(url, future=True, hide_parameters=True,
        pool_pre_ping=True, pool_timeout=settings.database_pool_timeout_seconds,
        connect_args={"connect_timeout": settings.database_connect_timeout_seconds,
            "target_session_attrs": "read-write", "options": options,
            "keepalives": 1, "keepalives_idle": 1, "keepalives_interval": 1,
            "keepalives_count": 3, "tcp_user_timeout": settings.database_tcp_user_timeout_ms},
        **overrides)
    event.listen(engine, "checkout", _require_writable)
    event.listen(engine, "handle_error", _invalidate_demoted_connection)
    return engine


def check_database_ready(engine) -> None:
    # Checkout performs the primary-role check for PostgreSQL. This also proves
    # the SQLite connection in development, without a schema mutation.
    with database_http_boundary():
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
