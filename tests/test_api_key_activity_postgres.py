"""Real row-lock proofs; only a private disposable Unix-socket PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from threading import Barrier, Event
import time

import pytest
from sqlalchemy import create_engine, event, or_, select, text, update
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from agentops_guard.backend.models import ApiKey
from agentops_guard.backend.services.api_keys import authenticate_api_key, create_api_key, hash_token


@pytest.fixture
def private_activity_pg():
    value = os.environ.get("AGENTOPS_ACTIVITY_TEST_SOCKET")
    if not value:
        pytest.skip("Requires the explicitly launched private activity PostgreSQL")
    socket = Path(value)
    assert socket.parent.parent == Path("/tmp")
    assert socket.parent.name.startswith("agentops-auth-lock-") and socket.name == "socket"
    assert (socket / ".s.PGSQL.5432").is_socket()
    url = URL.create("postgresql+psycopg", username="postgres", database="postgres",
                     query={"host": str(socket)})
    engine = create_engine(url, hide_parameters=True, pool_size=18, max_overflow=0,
                          connect_args={"connect_timeout": 2,
                                        "options": "-c statement_timeout=2000 -c lock_timeout=250"})
    ApiKey.__table__.create(engine, checkfirst=True)
    with Session(engine) as db:
        row, token = create_api_key(db, "controlled", "row-lock", ["runs:read"])
        key_id = row.id
        db.commit()
    try:
        yield engine, token, key_id
    finally:
        engine.dispose()


def valid_key_activity(db, token, mode):
    if mode == "skip_locked":
        return authenticate_api_key(db, token)
    # Controlled valid, unexpired key only: reproduce the former timestamp
    # write and a conditional-only candidate, not alternative authorization.
    row = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_token(token)))
    assert row is not None and row.revoked_at is None and row.expires_at is None
    current = datetime.now(UTC)
    if mode == "former_write":
        row.last_used_at = current
        db.flush()
    else:
        db.execute(update(ApiKey).where(ApiKey.id == row.id,
            or_(ApiKey.last_used_at.is_(None), ApiKey.last_used_at <= current - timedelta(seconds=60)))
            .values(last_used_at=current))
    return row


@pytest.mark.parametrize("trial", range(3))
@pytest.mark.parametrize("mode", ["former_write", "conditional_only", "skip_locked"])
def test_busy_activity_row_does_not_block_authentication(private_activity_pg, mode, trial, record_property):
    engine, token, key_id = private_activity_pg
    started = Event()
    worker_pid = []
    with engine.connect() as holder, engine.connect() as observer:
        holder.execute(select(ApiKey.id).where(ApiKey.id == key_id).with_for_update())
        holder_pid = holder.connection.driver_connection.info.backend_pid

        def authenticate():
            with Session(engine) as db:
                worker_pid.append(db.connection().connection.driver_connection.info.backend_pid)
                started.set()
                begin = time.monotonic()
                try:
                    assert valid_key_activity(db, token, mode) is not None
                    db.commit()
                    return "ok", time.monotonic() - begin
                except OperationalError as error:
                    return error.orig.sqlstate, time.monotonic() - begin

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(authenticate)
            assert started.wait(2)
            blocked = False
            deadline = time.monotonic() + 2
            while not future.done() and time.monotonic() < deadline:
                blocked |= bool(observer.scalar(text(
                    "SELECT :holder = ANY(pg_blocking_pids(:worker))"),
                    {"holder": holder_pid, "worker": worker_pid[0]}))
                observer.commit()
                time.sleep(0.005)
            outcome, elapsed = future.result(timeout=2)
        # The holder has NOT released its lock when authentication finishes.
        holder.rollback()
    record_property("mode", mode)
    record_property("trial", trial)
    record_property("outcome", outcome)
    record_property("blocked_by_controlled_holder", blocked)
    record_property("elapsed_ms", round(elapsed * 1000, 3))
    if mode == "skip_locked":
        assert outcome == "ok" and not blocked
        with Session(engine) as db:
            assert db.get(ApiKey, key_id).last_used_at is None
            authenticate_api_key(db, token)
            db.commit()
            assert db.get(ApiKey, key_id).last_used_at is not None
    else:
        assert outcome == "55P03" and blocked


def test_sixteen_simultaneous_refreshes_update_only_once(private_activity_pg):
    engine, token, key_id = private_activity_pg
    barrier = Barrier(16, timeout=5)
    updates = []

    def count(_connection, cursor, statement, *_args):
        if statement.startswith("UPDATE api_keys"):
            updates.append(cursor.rowcount)

    event.listen(engine, "after_cursor_execute", count)

    def authenticate(_index):
        with Session(engine) as db:
            db.connection()  # All connections exist before the simultaneous wave.
            barrier.wait()
            row = authenticate_api_key(db, token)
            db.commit()
            return row.id == key_id

    with ThreadPoolExecutor(max_workers=16) as executor:
        assert all(executor.map(authenticate, range(16)))
    event.remove(engine, "after_cursor_execute", count)
    assert sum(updates) == 1
    with Session(engine) as db:
        assert db.get(ApiKey, key_id).last_used_at is not None


def test_committed_revocation_not_hidden_by_fresh_activity(private_activity_pg):
    engine, token, key_id = private_activity_pg
    with Session(engine) as db:
        assert authenticate_api_key(db, token)
        db.commit()
    with engine.begin() as connection:
        connection.execute(update(ApiKey).where(ApiKey.id == key_id).values(revoked_at=datetime.now(UTC)))
    with Session(engine) as db:
        assert authenticate_api_key(db, token) is None
