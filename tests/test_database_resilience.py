from contextlib import contextmanager
import os
import secrets
import subprocess
import time

from fastapi import HTTPException
from fastapi.testclient import TestClient
import psycopg
import pytest
from sqlalchemy import event, exc, text
from sqlalchemy.engine import make_url

from agentops_guard.backend.config import Settings
from agentops_guard.backend.database_resilience import (
    check_database_ready, create_database_engine, database_http_boundary, database_unavailable,
)


@pytest.mark.parametrize('error', [exc.TimeoutError('pool'),
    exc.OperationalError('private sql', {'secret': 'private'}, psycopg.OperationalError('private endpoint')),
    exc.OperationalError('sql', {}, psycopg.errors.ReadOnlySqlTransaction('readonly')),
    exc.OperationalError('sql', {}, psycopg.errors.QueryCanceled('statement timeout')),
    exc.OperationalError('sql', {}, psycopg.errors.LockNotAvailable('lock timeout'))])
def test_unavailable_returns_sanitized_503_without_replaying(error):
    calls = []
    with pytest.raises(HTTPException) as caught:
        with database_http_boundary():
            calls.append('one attempt')
            raise error
    assert caught.value.status_code == 503
    assert caught.value.detail == 'Database temporarily unavailable'
    assert caught.value.headers is None
    assert calls == ['one attempt']


@pytest.mark.parametrize('error', [
    exc.IntegrityError('sql', {}, psycopg.errors.UniqueViolation('duplicate')),
    exc.ProgrammingError('sql', {}, psycopg.errors.SyntaxError('syntax')),
    ValueError('application bug'),
])
def test_non_availability_errors_are_not_hidden(error):
    assert not database_unavailable(error)
    with pytest.raises(type(error)) as caught:
        with database_http_boundary():
            raise error
    assert caught.value is error


def test_sqlite_is_unaffected_and_remains_ready():
    engine = create_database_engine(Settings(database_url='sqlite://'))
    try:
        check_database_ready(engine)
    finally:
        engine.dispose()


@pytest.fixture(scope='module')
def postgres_url():
    image = os.environ.get('AGENTOPS_TEST_POSTGRES_IMAGE')
    if not image:
        pytest.skip('Set AGENTOPS_TEST_POSTGRES_IMAGE for real PostgreSQL failover-boundary tests')
    name = 'agentops-db-boundary-' + secrets.token_hex(6)
    password = secrets.token_hex(24)
    command = ['docker', 'run', '--detach', '--name', name, '--publish', '127.0.0.1::5432',
               '--env-file', '/dev/stdin', image]
    result = subprocess.run(command, input='POSTGRES_PASSWORD='+password+'\n', text=True, capture_output=True)
    assert result.returncode == 0, 'disposable PostgreSQL startup failed'
    try:
        port = subprocess.run(['docker', 'port', name, '5432'], capture_output=True, text=True, check=True).stdout.strip().split(':')[-1]
        url = f'postgresql+psycopg://postgres:{password}@127.0.0.1:{port}/postgres'
        deadline = time.monotonic() + 30
        while True:
            try:
                with psycopg.connect(host='127.0.0.1', port=int(port), user='postgres', password=password, connect_timeout=2):
                    break
            except psycopg.OperationalError:
                if time.monotonic() > deadline:
                    pytest.fail('disposable PostgreSQL not ready', pytrace=False)
                time.sleep(.2)
        yield make_url(url)  # URL repr masks credentials in test failure reports.
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, check=True)


@contextmanager
def database(url, **options):
    engine = create_database_engine(Settings(database_url=url.render_as_string(hide_password=False), database_statement_timeout_ms=250,
        database_lock_timeout_ms=100, database_pool_timeout_seconds=.1), pool_size=1, max_overflow=0, **options)
    try:
        yield engine
    finally:
        engine.dispose()


def test_real_demoted_pooled_connection_is_replaced_before_business_transaction(postgres_url):
    with database(postgres_url) as engine:
        with engine.connect() as connection:
            old_pid = connection.scalar(text('SELECT pg_backend_pid()'))
            connection.execute(text('SET SESSION default_transaction_read_only = on'))
            connection.commit()
        with engine.begin() as connection:
            assert connection.scalar(text('SELECT pg_backend_pid()')) != old_pid
            connection.execute(text('CREATE TEMP TABLE checkout_write (id integer)'))
            connection.execute(text('INSERT INTO checkout_write VALUES (1)'))
            assert connection.scalar(text('SELECT count(*) FROM checkout_write')) == 1


def test_real_dead_pooled_connection_recovers(postgres_url):
    with database(postgres_url) as engine, database(postgres_url) as admin:
        with engine.connect() as connection:
            old_pid = connection.scalar(text('SELECT pg_backend_pid()'))
        with admin.begin() as connection:
            connection.execute(text('SELECT pg_terminate_backend(:pid)'), {'pid': old_pid})
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT pg_backend_pid()')) != old_pid


def test_real_readonly_checkout_retires_idle_peers_without_cancelling_active_work(postgres_url):
    engine = create_database_engine(Settings(
        database_url=postgres_url.render_as_string(hide_password=False)), pool_size=3, max_overflow=0)
    checked = []
    event.listen(engine, 'checkout', lambda connection, *_: checked.append(connection.info.backend_pid), insert=True)
    try:
        with engine.connect() as first, engine.connect() as peer, engine.begin() as active:
            old_first = first.scalar(text('SELECT pg_backend_pid()'))
            old_peer = peer.scalar(text('SELECT pg_backend_pid()'))
            active_pid = active.scalar(text('SELECT pg_backend_pid()'))
            # A real pending transaction must not be cancelled by pool invalidation.
            active.execute(text('CREATE TEMP TABLE active_checkout_work (id integer)'))
            active.execute(text('INSERT INTO active_checkout_work VALUES (1)'))
            for connection in (first, peer):
                connection.execute(text('SET SESSION default_transaction_read_only = on'))
                connection.commit()
            first.close()
            peer.close()
            checked.clear()
            with engine.connect() as replacement:
                assert replacement.scalar(text('SELECT pg_backend_pid()')) not in {old_first, old_peer}
            with engine.connect() as replacement:
                assert replacement.scalar(text('SELECT pg_backend_pid()')) not in {old_first, old_peer}
            assert old_first in checked  # This checkout discovered the role change.
            assert old_peer not in checked  # Retired before another business checkout probes it.
            assert active.scalar(text('SELECT pg_backend_pid()')) == active_pid
            assert active.scalar(text('SELECT count(*) FROM active_checkout_work')) == 1
        # Exiting engine.begin committed the pending work without any replay.
    finally:
        engine.dispose()


def test_real_sql_timeout_is_bounded_and_next_checkout_works(postgres_url):
    with database(postgres_url) as engine:
        started = time.monotonic()
        with pytest.raises(HTTPException) as caught:
            with database_http_boundary(), engine.begin() as connection:
                connection.execute(text('SELECT pg_sleep(10)'))
        assert caught.value.status_code == 503
        assert time.monotonic() - started < 2
        check_database_ready(engine)


def test_real_pool_and_lock_waits_are_bounded(postgres_url):
    with database(postgres_url) as engine, database(postgres_url) as peer:
        with engine.begin() as connection:
            connection.execute(text('CREATE TABLE IF NOT EXISTS lock_probe (id integer)'))
        with engine.begin() as held:
            held.execute(text('LOCK TABLE lock_probe IN ACCESS EXCLUSIVE MODE'))
            started = time.monotonic()
            with pytest.raises(HTTPException):
                with database_http_boundary(), engine.connect():
                    pytest.fail('exhausted pool allowed another checkout')
            assert time.monotonic() - started < 1
            started = time.monotonic()
            with pytest.raises(HTTPException):
                with database_http_boundary(), peer.begin() as connection:
                    connection.execute(text('INSERT INTO lock_probe VALUES (1)'))
            assert time.monotonic() - started < 1


def test_real_mid_transaction_readonly_never_replays_prior_write(postgres_url):
    with database(postgres_url) as engine:
        with engine.begin() as connection:
            connection.execute(text('CREATE TABLE IF NOT EXISTS no_replay (id integer)'))
        calls = []
        with pytest.raises(HTTPException):
            with database_http_boundary(), engine.begin() as connection:
                old_pid = connection.scalar(text('SELECT pg_backend_pid()'))
                connection.execute(text('INSERT INTO no_replay VALUES (1)'))
                calls.append('external action has already executed')
                # Simulate a demotion error after dispatch, without replaying it.
                connection.execute(text("DO $$ BEGIN RAISE EXCEPTION 'demoted' USING ERRCODE='25006'; END $$"))
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT pg_backend_pid()')) != old_pid
            assert connection.scalar(text('SELECT count(*) FROM no_replay')) == 0
        assert calls == ['external action has already executed']


def test_gateway_database_failure_removes_readiness_without_failing_liveness(monkeypatch):
    from agentops_guard.gateway import app as gateway

    class UnavailableEngine:
        def connect(self):
            raise exc.OperationalError('private sql', {}, psycopg.OperationalError('private endpoint'))

    monkeypatch.setattr(gateway, 'engine', UnavailableEngine())
    client = TestClient(gateway.app)
    assert client.get('/healthz').status_code == 200
    response = client.get('/readyz')
    assert response.status_code == 503
    assert response.json() == {'detail': 'Database temporarily unavailable'}


@pytest.mark.asyncio
async def test_standard_protocol_database_failure_is_safe_and_never_retried(monkeypatch):
    from agentops_guard.gateway import app as gateway
    from agentops_guard.gateway.protocol import _call_gateway
    from mcp.shared.exceptions import MCPError
    calls = []

    def unavailable(**kwargs):
        calls.append(1)
        raise exc.OperationalError('private sql', {}, psycopg.OperationalError('private endpoint'))

    monkeypatch.setattr(gateway, 'gateway_call_tool', unavailable, raising=False)
    with pytest.raises(MCPError) as caught:
        await _call_gateway('gateway_call_tool')
    assert caught.value.error.code == -32053
    assert caught.value.error.message == 'Service temporarily unavailable'
    assert calls == [1]


@pytest.mark.asyncio
@pytest.mark.parametrize('state', ['response_received', 'outcome_unknown'])
async def test_standard_protocol_preserves_post_tool_failure_state(monkeypatch, state):
    from agentops_guard.backend.database_resilience import PostToolDatabaseUnavailable
    from agentops_guard.gateway import app as gateway
    from agentops_guard.gateway.protocol import _call_gateway
    from mcp.shared.exceptions import MCPError
    calls = []
    outcome = {'state': state, 'tool_reported_error': False if state == 'response_received' else None,
               'result_released': False, 'automatic_retry_allowed': False}

    def unavailable(**kwargs):
        calls.append(1)
        raise PostToolDatabaseUnavailable(outcome)

    monkeypatch.setattr(gateway, 'gateway_call_tool', unavailable, raising=False)
    with pytest.raises(MCPError) as caught:
        await _call_gateway('gateway_call_tool')
    assert caught.value.error.code == -32053
    assert caught.value.error.data == {'code': 'post_tool_database_unavailable', 'tool_execution': outcome}
    assert calls == [1]
