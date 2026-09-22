"""Run separately, behind TLS. No business authentication or business readiness dependency."""
import asyncio
from contextlib import asynccontextmanager, suppress
import json
import random
from threading import Event
import time
from uuid import UUID

import anyio
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
import psycopg
from sqlalchemy import event, exc, text

from agentops_guard.admission.store import AdmissionSettings, Store, public_status
from agentops_guard.backend.database_resilience import database_http_boundary


def retryable_admission_error(error):
    # Retrying this ID-bound ledger transaction cannot replay a tool. Do not
    # treat database authentication, integrity or programming errors as failover.
    if isinstance(error, exc.TimeoutError):
        return True
    if not isinstance(error, exc.DBAPIError):
        return False
    code = getattr(error.orig, "sqlstate", None)
    if code is not None:
        return code.startswith("08") or code in {"25006", "57P01", "57P02", "57P03", "55P03", "57014"}
    return error.connection_invalidated or isinstance(error.orig, psycopg.OperationalError)


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    requestId: str = Field(min_length=36, max_length=36)
    serverId: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    arguments: dict = Field(default_factory=dict)
    runId: str | None = Field(default=None, min_length=1, max_length=64)


def create_app(settings=None, *, store=None):
    settings = settings or AdmissionSettings()
    owns_store = store is None
    store = store or Store(settings, isolate_queries=True)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            if owns_store:
                store.dispose()

    app = FastAPI(title="AgentOps admission pilot", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.store = store
    readiness_limiter = anyio.CapacityLimiter(1)
    submission_limiter = anyio.CapacityLimiter(12)
    query_limiter = anyio.CapacityLimiter(3)

    def enabled():
        if not settings.enabled:
            raise HTTPException(503, "Independent admission is disabled")

    async def recover_database(request, operation, *, durability_confirmed=False):
        token = request.headers.get("X-AgentOps-Admission-Key")
        if not token or len(token) > 256:
            raise HTTPException(401, "Admission credential required")
        deadline = time.monotonic() + settings.request_timeout_seconds
        stopped = Event()
        engine = store.engine if durability_confirmed else store.query_engine
        limiter = submission_limiter if durability_confirmed else query_limiter

        def checkpoint():
            if stopped.is_set() or time.monotonic() >= deadline:
                raise TimeoutError
            anyio.from_thread.check_cancelled()

        def attempt():
            checkpoint()
            try:
                connection = engine.connect()
            except exc.InvalidRequestError as error:
                # SQLAlchemy exhausts its own checkout reconnect attempts with
                # this non-DBAPI error. Only translate that checkout failure;
                # unrelated transaction/programming errors must still surface.
                if error.args != ("This connection is closed",):
                    raise
                raise exc.OperationalError(None, None, psycopg.OperationalError(
                    "Admission database checkout temporarily unavailable")) from None
            # Keep this connection exclusively checked out until listeners are
            # removed, including the COMMIT-notice confirmation guard.
            with connection, store.sessions(bind=connection) as db:
                checkpoint()

                def before_sql(*_args):
                    checkpoint()

                # Check application SQL, including ORM flushes. In-flight
                # checkout probes may finish after cancellation; application
                # SQL must not begin another step after the checkpoint fails.
                event.listen(connection, "before_cursor_execute", before_sql)
                event.listen(connection, "commit", before_sql)
                try:
                    return public_status(operation(db, token, checkpoint),
                                         durability_confirmed=durability_confirmed)
                finally:
                    event.remove(connection, "before_cursor_execute", before_sql)
                    event.remove(connection, "commit", before_sql)

        with anyio.move_on_after(settings.request_timeout_seconds) as budget:
            async def watch_disconnect():
                while not await request.is_disconnected():
                    await anyio.sleep(0.05)
                budget.cancel()

            watcher = asyncio.create_task(watch_disconnect())
            try:
                delay = 0.1
                while True:
                    try:
                        return await anyio.to_thread.run_sync(attempt, abandon_on_cancel=True, limiter=limiter)
                    except (exc.DBAPIError, exc.TimeoutError) as error:
                        if not retryable_admission_error(error):
                            raise
                    except TimeoutError:
                        break
                    # Only an explicit transient DB failure reaches this path.
                    # The next fresh session repeats current authentication.
                    await anyio.sleep(random.uniform(delay / 2, delay))
                    delay = min(delay * 2, 0.5)
            finally:
                stopped.set()
                watcher.cancel()
                with anyio.CancelScope(shield=True), suppress(asyncio.CancelledError):
                    await watcher
        # An already-started COMMIT cannot be recalled. No acknowledgement is
        # fabricated; the original request ID remains the only query/retry key.
        raise HTTPException(503, "Database temporarily unavailable")

    @app.get("/healthz")
    async def healthy():
        return {"alive": True}

    @app.get("/recoveryz")
    async def recovery_ready():
        enabled()
        # Routing to the bounded recovery handler is NOT a claim that its DB
        # can commit. Preserve /readyz as the separate, honest dependency probe.
        return {"servingRecovery": True, "acceptanceRequiresDatabaseCommit": True}

    def probe_schema():
        enabled()
        with database_http_boundary(), store.sessions(bind=store.query_engine) as db:
            # Prove the schema exists, not just a reachable port.
            db.execute(text("SELECT id FROM admission_grants_v1 LIMIT 0"))
        return {"ready": True}

    @app.get("/readyz")
    async def ready():
        # Dependency probes must not occupy all business worker threads or
        # block the event loop that delivers bounded rejection/status replies.
        return await anyio.to_thread.run_sync(probe_schema, limiter=readiness_limiter)

    @app.post("/v1/admissions")
    async def submit(request: Request):
        enabled()
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 65536:
                raise HTTPException(413, "Admission payload exceeds 64 KiB")
        try:
            parsed = Submission.model_validate(json.loads(raw))
            payload = parsed.model_dump(exclude_unset=True)
            payload["requestId"] = str(UUID(parsed.requestId))
        except (ValueError, ValidationError):
            raise HTTPException(400, "Invalid admission request") from None

        response = await recover_database(request,
            lambda db, token, checkpoint: store.accept(db, token, payload, before_commit=checkpoint),
            durability_confirmed=True)
        return JSONResponse(response, status_code=202, headers={"Cache-Control": "no-store"})

    @app.get("/v1/admissions/{request_id}")
    async def lookup(request_id: str, request: Request):
        enabled()
        try:
            request_id = str(UUID(request_id))
        except ValueError:
            raise HTTPException(400, "Invalid request ID") from None
        result = await recover_database(request,
            lambda db, token, _checkpoint: store.lookup(db, token, request_id))
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    return app
