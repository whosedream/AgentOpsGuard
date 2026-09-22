"""Real PostgreSQL + Redis/RQ + MCP; process loss is injected at a named boundary."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from threading import Barrier, Lock
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest
from redis import Redis
from rq import Queue, SimpleWorker
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from test_database_resilience import postgres_url as postgres_url, database
from test_gateway_streamable_http_transport import standard_mcp_server as standard_mcp_server
from agentops_guard.backend.config import Settings, get_settings
from agentops_guard.backend.database import Base, get_db
from agentops_guard.backend.database_resilience import (
    create_database_engine,
    database_http_boundary,
)
from agentops_guard.backend.models import (
    BackgroundJob,
    McpServer,
    McpTool,
    OutboxEvent,
    ToolInvocation,
    ToolExecutionPolicy,
)
from agentops_guard.backend.services.api_keys import create_api_key
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services import jobs, tool_invocations as receipts
from agentops_guard.gateway import app as gateway
from agentops_guard.gateway.auth import GatewayIdentity


@pytest.mark.parametrize("lose_after_tool", [False, True])
@pytest.mark.parametrize("lose_notification", [False, True])
def test_real_queue_gateway_and_mcp_recovery(
    postgres_url, standard_mcp_server, monkeypatch, lose_after_tool, lose_notification
):
    redis_url = os.environ.get("AGENTOPS_TEST_REDIS_URL")
    if not redis_url:
        pytest.skip("Set AGENTOPS_TEST_REDIS_URL for real Redis integration")
    redis = Redis.from_url(redis_url)
    redis.ping()
    project, server, queue_name = (
        "invpg_" + uuid4().hex,
        "mcp_" + uuid4().hex,
        "invq_" + uuid4().hex,
    )
    monkeypatch.setattr(
        get_settings(), "invocation_encryption_key", SecretStr(Fernet.generate_key().decode())
    )
    with database(postgres_url) as engine:
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL statement_timeout = '10s'"))
            Base.metadata.create_all(connection)
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        with sessions() as db:
            ensure_project(db, project)
            db.add(
                McpServer(
                    id=server,
                    project_id=project,
                    name="real MCP",
                    transport="streamable_http",
                    url=standard_mcp_server,
                    trust_level="internal",
                    status="active",
                    allowed_agents=[],
                )
            )
            db.add(
                McpTool(
                    id=server + ":echo",
                    server_id=server,
                    project_id=project,
                    name="echo",
                    description="Return text",
                    status="active",
                    annotations={},
                    input_schema={"type": "object", "properties": {"text": {"type": "string"}}},
                )
            )
            key, token = create_api_key(
                db, project, "runtime-test", ["mcp:*"], agent_id="runtime-agent"
            )
            revision = receipts.current_revision(db, project, server + ":echo")
            db.add(
                ToolExecutionPolicy(
                    tool_id=server + ":echo",
                    project_id=project,
                    revision_digest=revision.content_digest,
                    queue_enabled=True,
                    retry_mode="read_only",
                    evidence_sha256="b" * 64,
                    updated_by="test-admin",
                )
            )
            db.commit()

        def scoped_db():
            with database_http_boundary(), sessions() as db:
                yield db

        monkeypatch.setitem(gateway.app.dependency_overrides, get_db, scoped_db)
        monkeypatch.setattr(jobs, "SessionLocal", sessions)
        monkeypatch.setattr(jobs, "redis_connection", lambda **kw: redis)
        actual_call = gateway._call_upstream_tool
        calls = []

        def observed_call(*args):
            result = actual_call(*args)
            calls.append(result)
            if lose_after_tool:
                raise RuntimeError("injected worker loss after real MCP response")
            return result

        monkeypatch.setattr(gateway, "_call_upstream_tool", observed_call)
        client = TestClient(gateway.app, headers={"X-AgentOps-Api-Key": token})
        request_id = str(uuid4())
        payload = {
            "requestId": request_id,
            "serverId": server,
            "name": "echo",
            "arguments": {"text": "runtime harmless text"},
        }
        accepted = client.post("/mcp/invocations", json=payload)
        assert accepted.status_code == 202 and accepted.json()["state"] == "queued"
        assert calls == []
        with sessions() as db:
            row = db.query(ToolInvocation).filter_by(project_id=project).one()
            invocation_id, job_id = row.id, row.job_id
            event = db.get(OutboxEvent, "outbox_" + job_id)
            event.payload = {"job_id": job_id, "queue_name": queue_name}
            db.commit()
            assert jobs.dispatch_outbox_batch(db, dispatcher_id="real-runtime") == 1
        queue = Queue(queue_name, connection=redis)
        try:
            assert len(queue) == 1
            queued_job = queue.get_jobs()[0]
            assert queued_job.args == (job_id,)
            assert "runtime harmless text" not in str(redis.hgetall(queued_job.key))
            if lose_notification:
                # Delete only this test's unconsumed notification, not Redis
                # as a whole. The database outbox remains delivered.
                queue.remove(queued_job.id)
                queued_job.delete()
                with sessions() as db:
                    db.get(BackgroundJob, job_id).created_at = datetime.now(UTC) - timedelta(seconds=90)
                    db.get(OutboxEvent, "outbox_" + job_id).delivered_at = datetime.now(UTC) - timedelta(seconds=60)
                    db.commit()
                    assert jobs.reconcile_missing_tool_deliveries(db)[0] == 1
                    db.commit()
                    assert jobs.reconcile_missing_tool_deliveries(db)[0] == 0
                    db.commit()
                    assert jobs.dispatch_outbox_batch(db, dispatcher_id="replacement-notification") == 1
                assert len(queue.get_jobs()) == 1
            SimpleWorker([queue], connection=redis).work(burst=True, logging_level="CRITICAL")
            if lose_after_tool:
                with sessions() as db:
                    row = db.get(ToolInvocation, invocation_id)
                    assert row.status == "outcome_unknown"
                    assert db.get(BackgroundJob, job_id).status == "completed"
                    # A known worker failure after dispatch is settled, not
                    # re-enqueued just to discover again that it is unknown.
                    assert db.get(OutboxEvent, f"outbox_retry_{job_id}_1") is None
            expected = "outcome_unknown" if lose_after_tool else "succeeded"
            state = client.get("/mcp/invocations/" + request_id).json()
            assert state["state"] == expected and state["attempts"] == 1
            # Duplicate client submission and a separately delivered RQ job both
            # retrieve the receipt; even reviewed reads are not crash-replayed.
            assert client.post("/mcp/invocations", json=payload).json()["state"] == expected
            queue.enqueue("agentops_guard.backend.services.jobs.execute_job", job_id)
            SimpleWorker([queue], connection=redis).work(burst=True, logging_level="CRITICAL")
            assert len(calls) == 1 and calls[0].get("isError") is False
            with sessions() as db:
                assert db.get(BackgroundJob, job_id).result["state"] == expected
        finally:
            queue.delete(delete_jobs=True)


def test_real_postgres_concurrent_receipt_has_one_dispatch(postgres_url):
    engine = create_database_engine(
        Settings(database_url=postgres_url.render_as_string(hide_password=False)),
        pool_size=4,
        max_overflow=0,
    )
    try:
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL statement_timeout = '10s'"))
            Base.metadata.create_all(connection)
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        identity = GatewayIdentity("parallel_" + uuid4().hex, "operator", "operator", None, None)
        payload = {"requestId": str(uuid4()), "serverId": "server", "name": "echo", "arguments": {}}
        ready, lock, calls = Barrier(4), Lock(), []

        def perform(payload, identity, db, *, invocation_attempt):
            invocation_attempt.dispatch(db, "a" * 64)
            with lock:
                calls.append("effect")
            return {"isError": False, "content": []}

        def submit():
            with sessions() as db:
                ready.wait(timeout=5)
                row, created = receipts.register(db, payload, identity, queued=False)
                if created:
                    receipts.execute(db, row, payload, identity, perform)
                return created

        with ThreadPoolExecutor(max_workers=4) as workers:
            created = list(workers.map(lambda _: submit(), range(4)))
        assert sum(created) == 1 and calls == ["effect"]
    finally:
        engine.dispose()
