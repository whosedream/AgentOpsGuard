"""Recovery routing stays distinct from DB readiness and durable acceptance."""
from datetime import timedelta
from hashlib import sha256
import secrets
from threading import Event
from uuid import uuid4

import anyio
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import httpx
import psycopg
import pytest
from sqlalchemy import exc

from agentops_guard.admission.app import create_app
from agentops_guard.admission.store import AdmissionSettings, Entry, Grant, Store, now


def seed_health_store(store):
    token = "admission_" + secrets.token_urlsafe(32)
    grant_id = "grant_" + uuid4().hex
    with store.sessions() as db:
        db.add(Grant(id=grant_id, token_hash=sha256(token.encode()).hexdigest(),
            project_id=grant_id, actor_digest=grant_id, subject={}, tools={"controlled:read": {}},
            expires_at=now() + timedelta(hours=1)))
        db.commit()
    return token, grant_id, {"requestId": str(uuid4()), "serverId": "controlled", "name": "read", "arguments": {}}


@pytest.fixture
def health_store(tmp_path):
    settings = AdmissionSettings(enabled=True, allow_test_sqlite=True,
        database_url=f"sqlite:///{tmp_path / 'health.db'}", encryption_key=Fernet.generate_key().decode(),
        request_timeout_seconds=1)
    store = Store(settings, isolate_queries=True)
    store.initialize()
    try:
        yield store, seed_health_store(store)
    finally:
        store.dispose()


def test_routing_does_not_claim_database_ready_or_confirm_deposit(health_store, monkeypatch):
    store, (token, _, payload) = health_store
    original = store.engine.connect

    def disconnected():
        raise exc.OperationalError(None, None, psycopg.OperationalError("controlled private endpoint"))

    with TestClient(create_app(store.settings, store=store)) as client:
        client.headers["X-AgentOps-Admission-Key"] = token
        assert client.get("/readyz").status_code == 200
        accepted = client.post("/v1/admissions", json=payload)
        assert accepted.status_code == 202 and accepted.json()["durabilityConfirmed"]
        monkeypatch.setattr(store.engine, "connect", disconnected)
        assert client.get("/healthz").json() == {"alive": True}
        assert client.get("/recoveryz").json() == {
            "servingRecovery": True, "acceptanceRequiresDatabaseCommit": True}
        assert client.get("/readyz").status_code == 503
        for response in (client.post("/v1/admissions", json={**payload, "requestId": str(uuid4())}),
                         client.get("/v1/admissions/" + payload["requestId"])):
            assert response.status_code == 503
            assert response.json() == {"detail": "Database temporarily unavailable"}
            assert "private" not in response.text
        monkeypatch.setattr(store.engine, "connect", original)
        status = client.get("/v1/admissions/" + payload["requestId"])
        assert status.status_code == 200 and not status.json()["durabilityConfirmed"]
        with store.sessions() as db:
            assert db.query(Entry).count() == 1
        store.settings.enabled = False
        assert client.get("/recoveryz").status_code == 503
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200


@pytest.mark.asyncio
async def test_health_and_readiness_do_not_wait_for_default_worker_threads(health_store):
    store, _ = health_store
    limiter = anyio.to_thread.current_default_thread_limiter()
    original = limiter.total_tokens
    limiter.total_tokens = 1
    entered, release = Event(), Event()

    def occupied():
        entered.set()
        release.wait(timeout=3)

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(anyio.to_thread.run_sync, occupied)
            try:
                with anyio.fail_after(1):
                    while not entered.is_set():
                        await anyio.sleep(.001)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(store.settings, store=store)),
                                             base_url="http://controlled.invalid") as client:
                    with anyio.fail_after(.5):
                        for path in ("/healthz", "/recoveryz", "/readyz"):
                            assert (await client.get(path)).status_code == 200
                assert not release.is_set()
            finally:
                release.set()
    finally:
        limiter.total_tokens = original
