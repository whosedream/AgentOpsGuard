"""RQ's child must use fresh DB connections while leaving its parent intact."""

import json
import os
from pathlib import Path
import select
import signal
from types import SimpleNamespace

import pytest
from rq import Worker
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from agentops_guard.backend import worker


def test_child_resets_pool_before_rq_job_initialization(monkeypatch):
    calls = []
    monkeypatch.setattr(worker, "engine", SimpleNamespace(dispose=lambda **kwargs: calls.append(("dispose", kwargs))))
    monkeypatch.setattr(Worker, "main_work_horse", lambda self, job, queue: calls.append(("rq", job, queue)))
    instance = object.__new__(worker.DatabaseSafeWorker)
    instance.main_work_horse("controlled-job", "controlled-queue")
    assert calls == [("dispose", {"close": False}), ("rq", "controlled-job", "controlled-queue")]


def test_child_does_not_start_job_if_pool_replacement_fails(monkeypatch):
    calls = []

    def fail(**_kwargs):
        raise RuntimeError("controlled pool initialization failure")

    monkeypatch.setattr(worker, "engine", SimpleNamespace(dispose=fail))
    monkeypatch.setattr(Worker, "main_work_horse", lambda *args: calls.append("job_started"))
    with pytest.raises(RuntimeError, match="pool initialization"):
        object.__new__(worker.DatabaseSafeWorker).main_work_horse(None, None)
    assert calls == []


def test_cli_uses_safe_worker_and_keeps_queue_execution_options(monkeypatch):
    from agentops_guard import cli

    assert cli.DatabaseSafeWorker is worker.DatabaseSafeWorker
    calls = []
    connection = SimpleNamespace(ping=lambda: calls.append("redis_ping"))
    monkeypatch.setattr(cli, "configure_telemetry", lambda name: calls.append(name))
    monkeypatch.setattr(cli, "init_db", lambda: calls.append("init_db"))
    monkeypatch.setattr(cli, "redis_connection", lambda: connection)
    monkeypatch.setattr(cli, "Queue", lambda name, **kwargs: (name, kwargs["connection"]))
    monkeypatch.setattr(worker.DatabaseSafeWorker, "__init__",
                        lambda self, queues, **kwargs: calls.append(("worker", queues, kwargs["connection"])))
    monkeypatch.setattr(worker.DatabaseSafeWorker, "work", lambda self, **kwargs: calls.append(("work", kwargs)))
    cli.worker(queue="controlled", burst=True, with_scheduler=True)
    assert calls == ["agentops-guard-worker", "init_db", "redis_ping",
                     ("worker", [("controlled", connection)], connection),
                     ("work", {"burst": True, "with_scheduler": True})]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="RQ fork isolation requires Unix")
def test_real_postgresql_fork_uses_new_backend_and_preserves_parent(monkeypatch):
    socket = os.environ.get("AGENTOPS_FORK_TEST_SOCKET")
    if not socket:
        pytest.skip("Set the private disposable PostgreSQL socket for the real fork test")
    socket_path = Path(socket)
    assert (socket_path.parent.parent == Path("/tmp")
            and socket_path.parent.name.startswith("agentops-pg-fork-")
            and socket_path.name == "socket"
            and (socket_path / ".s.PGSQL.5432").is_socket())
    url = URL.create("postgresql+psycopg", username="postgres", database="postgres",
                     query={"host": socket})
    engine = create_engine(url, hide_parameters=True, pool_pre_ping=True,
                           pool_size=2, max_overflow=0, pool_timeout=2,
                           connect_args={"connect_timeout": 2,
                                         "options": "-c statement_timeout=3000"})
    monkeypatch.setattr(worker, "engine", engine)
    try:
        with engine.connect() as retained:
            retained_backend = retained.connection.driver_connection.info.backend_pid
            with engine.connect() as pooled:
                pooled_backend = pooled.connection.driver_connection.info.backend_pid
                for _ in range(7):
                    assert pooled.execute(text("SELECT 41::integer")).scalar_one() == 41
                pooled.commit()
            parent_backends = {retained_backend, pooled_backend}

            def perform_controlled_job(_self, _job, _queue):
                with engine.connect() as connection:
                    assert connection.connection.driver_connection.info.backend_pid not in parent_backends
                    assert connection.connection.driver_connection.prepare_threshold == 5
                    for _ in range(7):
                        assert connection.execute(text("SELECT CAST(:value AS integer)"), {"value": 17}).scalar_one() == 17
                    connection.commit()

            monkeypatch.setattr(Worker, "main_work_horse", perform_controlled_job)
            for _ in range(2):
                reader, writer = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(reader)
                    result = {"ok": True}
                    try:
                        object.__new__(worker.DatabaseSafeWorker).main_work_horse(None, None)
                    except Exception as error:
                        original = getattr(error, "orig", error)
                        result = {"ok": False, "error_class": type(error).__name__,
                                  "sqlstate": getattr(original, "sqlstate", None)}
                    finally:
                        os.write(writer, json.dumps(result).encode())
                        os.close(writer)
                        os._exit(0)
                os.close(writer)
                try:
                    if not select.select([reader], [], [], 10)[0]:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        pytest.fail("controlled fork child timed out", pytrace=False)
                    result = json.loads(os.read(reader, 65536))
                    _, status = os.waitpid(pid, 0)
                    assert status == 0
                    assert result == {"ok": True}, result
                finally:
                    os.close(reader)
                assert retained.connection.driver_connection.info.backend_pid == retained_backend
                assert retained.execute(text("SELECT 29::integer")).scalar_one() == 29
                retained.commit()
                with engine.connect() as pooled:
                    assert pooled.connection.driver_connection.info.backend_pid == pooled_backend
                    assert pooled.execute(text("SELECT 41::integer")).scalar_one() == 41
                    pooled.commit()
    finally:
        engine.dispose()
