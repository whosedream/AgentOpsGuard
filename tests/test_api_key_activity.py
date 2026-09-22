"""Optional activity writes never replace fresh authentication or wait on rows."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, exc, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from agentops_guard.backend.models import ApiKey
from agentops_guard.backend.services import api_keys


@pytest.fixture
def activity_db(monkeypatch):
    instant = datetime(2026, 9, 9, 9, tzinfo=UTC)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant if tz else instant.replace(tzinfo=None)

    monkeypatch.setattr(api_keys, "datetime", Clock)
    engine = create_engine("sqlite:///:memory:")
    ApiKey.__table__.create(engine)
    with Session(engine) as db:
        row, token = api_keys.create_api_key(db, "controlled", "activity", ["runs:read"])
        key_id = row.id
        db.commit()
    try:
        yield engine, token, key_id, instant
    finally:
        engine.dispose()


def test_first_activity_is_caller_committed_without_dirty_rewrite(activity_db):
    engine, token, key_id, instant = activity_db
    statements = []
    event.listen(engine, "before_cursor_execute", lambda _, __, sql, *args: statements.append(sql))
    with Session(engine) as db:
        row = api_keys.authenticate_api_key(db, token)
        assert row.last_used_at.replace(tzinfo=UTC) == instant
        assert row not in db.dirty
        db.rollback()
    with Session(engine) as db:
        assert db.get(ApiKey, key_id).last_used_at is None
        api_keys.authenticate_api_key(db, token)
        db.commit()
    assert sum(sql.startswith("UPDATE api_keys") for sql in statements) == 2


@pytest.mark.parametrize("age,updates", [(59, 0), (60, 1), (61, 1), (-5, 0)])
def test_refresh_window_and_clock_regression(activity_db, age, updates):
    engine, token, key_id, instant = activity_db
    previous = instant - timedelta(seconds=age)
    with Session(engine) as db:
        db.execute(update(ApiKey).where(ApiKey.id == key_id).values(last_used_at=previous))
        db.commit()
    statements = []
    event.listen(engine, "before_cursor_execute", lambda _, __, sql, *args: statements.append(sql))
    for _ in range(3):
        with Session(engine) as db:
            assert api_keys.authenticate_api_key(db, token) is not None
            db.commit()
    assert sum(sql.startswith("UPDATE api_keys") for sql in statements) == updates
    with Session(engine) as db:
        actual = db.get(ApiKey, key_id).last_used_at.replace(tzinfo=UTC)
        assert actual == (instant if updates else previous)


@pytest.mark.parametrize("change", ["revoked", "expired", "invalid_token"])
def test_recent_activity_never_caches_authorization(activity_db, change):
    engine, token, key_id, instant = activity_db
    with Session(engine) as db:
        assert api_keys.authenticate_api_key(db, token)
        db.commit()
    with Session(engine) as db:
        if change != "invalid_token":
            field = "revoked_at" if change == "revoked" else "expires_at"
            db.execute(update(ApiKey).where(ApiKey.id == key_id).values({field: instant}))
            db.commit()
    with Session(engine) as db:
        assert api_keys.authenticate_api_key(db, token if change != "invalid_token" else "invalid") is None


def test_authentication_read_failure_is_not_ignored(activity_db):
    engine, token, _, _ = activity_db

    def unavailable(*_args):
        raise exc.OperationalError(None, None, RuntimeError("controlled database failure"))

    event.listen(engine, "before_cursor_execute", unavailable)
    with Session(engine) as db, pytest.raises(exc.OperationalError):
        api_keys.authenticate_api_key(db, token)


def test_display_update_uses_postgres_skip_locked_only_after_plain_read(activity_db):
    engine, token, _, _ = activity_db
    clauses = []
    event.listen(engine, "before_execute", lambda _, clause, *args: clauses.append(clause))
    with Session(engine) as db:
        api_keys.authenticate_api_key(db, token)
    assert len(clauses) == 2
    sql = [str(clause.compile(dialect=postgresql.dialect())) for clause in clauses]
    assert "FOR UPDATE" not in sql[0]
    assert "FOR UPDATE SKIP LOCKED" in sql[1]
    assert "revoked_at IS NULL" in sql[1]
    assert "expires_at" in sql[1] and "last_used_at" in sql[1]
    assert isinstance(clauses[0], type(select(ApiKey)))
