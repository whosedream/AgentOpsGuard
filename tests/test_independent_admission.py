from datetime import timedelta
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import event, exc
import psycopg

from test_tool_invocations import setup_invocation as setup_invocation, review
from agentops_guard.admission.app import create_app, retryable_admission_error
from agentops_guard.admission.importer import handoff, provision
from agentops_guard.admission.store import AdmissionSettings, Entry, Grant, Store, now
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import ApiKey, BackgroundJob, OutboxEvent, ToolExecutionPolicy, ToolInvocation
from agentops_guard.backend.services import jobs


@pytest.fixture
def admission(setup_invocation, tmp_path):
    project, server, _, payload, _ = setup_invocation
    review(project, server)
    settings = AdmissionSettings(enabled=True, allow_test_sqlite=True,
        database_url=f"sqlite:///{tmp_path / 'separate.db'}", encryption_key=Fernet.generate_key().decode(),
        request_timeout_seconds=1)
    store = Store(settings)
    store.initialize()
    with SessionLocal() as db:
        key = db.query(ApiKey).filter_by(project_id=project).one()
        grant_id, token = provision(store, db, key_id=key.id, tool_ids=[server + ":demo.echo"])
    client = TestClient(create_app(settings, store=store))
    client.headers["X-AgentOps-Admission-Key"] = token
    try:
        yield store, client, payload, grant_id, setup_invocation
    finally:
        client.close()
        store.engine.dispose()


def force_due(store):
    with store.sessions() as db:
        db.query(Entry).update({"next_check_at": now() - timedelta(seconds=1),
                               "lease_until": now() - timedelta(seconds=1)})
        db.commit()


def test_checkout_reconnect_exhaustion_recovers_without_tool_replay(admission):
    store, client, payload, _, setup = admission
    attempts = []

    def invalidate_twice(*_args):
        attempts.append(True)
        if len(attempts) <= 2:
            raise exc.InvalidatePoolError()

    event.listen(store.engine, "checkout", invalidate_twice)
    try:
        response = client.post("/v1/admissions", json=payload)
        assert response.status_code == 202
        assert response.json()["durabilityConfirmed"] is True
        assert len(attempts) == 3
    finally:
        event.remove(store.engine, "checkout", invalidate_twice)
    with store.sessions() as db:
        assert db.query(Entry).count() == 1
    assert setup[4] == []


@pytest.mark.parametrize("at_checkout", [True, False])
def test_unrelated_invalid_request_is_not_retried(admission, monkeypatch, at_checkout):
    store, client, payload, _, _ = admission
    attempts = []
    message = "Invalid transaction usage" if at_checkout else "This connection is closed"

    def invalid(*_args, **_kwargs):
        attempts.append(True)
        raise exc.InvalidRequestError(message)

    monkeypatch.setattr(store.engine if at_checkout else store,
                        "connect" if at_checkout else "accept", invalid)
    with pytest.raises(exc.InvalidRequestError, match=message):
        client.post("/v1/admissions", json=payload)
    assert len(attempts) == 1


def test_accept_duplicate_conflict_and_status_have_no_business_dependency(admission):
    store, client, payload, _, setup = admission
    result = client.post("/v1/admissions", json=payload)
    assert result.status_code == 202, result.text
    assert result.json()["state"] == "accepted" and not result.json()["resultIncluded"]
    assert result.json()["durabilityConfirmed"] and result.json()["acceptanceEvidence"] == "commit_confirmed"
    for _ in range(10):
        assert client.post("/v1/admissions", json=payload).json() == result.json()
    assert client.post("/v1/admissions", json={**payload, "arguments": {"text": "different"}}).status_code == 409
    assert client.get("/v1/admissions/" + payload["requestId"]).json() == {
        **result.json(), "durabilityConfirmed": False, "acceptanceEvidence": "record_observed"}
    with SessionLocal() as db:
        assert db.query(ToolInvocation).filter_by(project_id=setup[0]).count() == 0
    with store.sessions() as db:
        row = db.query(Entry).one()
        assert row.encrypted_payload and payload["arguments"]["text"] not in row.encrypted_payload
        assert db.query(Entry).count() == 1


def test_handoff_commit_then_crash_is_idempotent_and_runs_existing_worker(admission):
    store, client, payload, _, setup = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202

    def crash():
        raise RuntimeError("controlled importer exit after business commit")

    with pytest.raises(RuntimeError, match="controlled importer"):
        handoff(store, SessionLocal, store.claim(), after_business_commit=crash)
    assert client.get("/v1/admissions/" + payload["requestId"]).json()["state"] == "accepted"
    force_due(store)
    assert handoff(store, SessionLocal, store.claim())
    with SessionLocal() as db:
        invocation = db.query(ToolInvocation).filter_by(project_id=setup[0]).one()
        job_id = invocation.job_id
        assert db.query(BackgroundJob).filter_by(id=job_id).count() == 1
        assert db.query(OutboxEvent).filter_by(project_id=setup[0]).count() == 1
    assert jobs.execute_job(job_id)["state"] == "succeeded"
    force_due(store)
    handoff(store, SessionLocal, store.claim())
    result = client.get("/v1/admissions/" + payload["requestId"]).json()
    assert result["state"] == "completed" and result["businessState"] == "succeeded"
    assert result["businessObservedAt"] and result["businessStatusIsSnapshot"]
    assert len(setup[4]) == 1


def test_business_db_unavailable_preserves_acceptance(admission):
    store, client, payload, _, _ = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202

    def unavailable():
        raise exc.OperationalError("hidden SQL", {}, psycopg.OperationalError("hidden endpoint"))

    assert handoff(store, unavailable, store.claim())
    status = client.get("/v1/admissions/" + payload["requestId"]).json()
    assert status["state"] == "accepted" and status["businessState"] is None
    assert status["reason"] == "business_temporarily_unavailable"
    assert "hidden" not in str(status)
    with store.sessions() as db:
        assert db.query(Entry).one().encrypted_payload


def test_acceptance_commit_reply_loss_is_queryable_without_new_work(admission, monkeypatch):
    store, client, payload, _, _ = admission
    original = store.sessions.class_.commit
    commits = []

    def lose_confirmation(self):
        original(self)
        commits.append(self)
        if len(commits) == 1:
            raise exc.OperationalError("hidden", {}, psycopg.OperationalError("hidden"))

    monkeypatch.setattr(store.sessions.class_, "commit", lose_confirmation)
    assert client.post("/v1/admissions", json=payload).status_code == 202
    assert len(commits) == 2 and commits[0] is not commits[1]
    assert client.get("/v1/admissions/" + payload["requestId"]).json()["accepted"]
    assert client.post("/v1/admissions", json=payload).status_code == 202
    with store.sessions() as db:
        assert db.query(Entry).count() == 1


def test_visible_duplicate_still_requires_fresh_commit_confirmation(admission, monkeypatch):
    store, client, payload, _, setup = admission
    first = client.post("/v1/admissions", json=payload).json()
    original = store.sessions.class_.commit
    commits = []

    def lose_every_confirmation(self):
        original(self)
        commits.append(self)
        raise exc.OperationalError("hidden SQL", {}, psycopg.OperationalError("hidden DSN"))

    monkeypatch.setattr(store.sessions.class_, "commit", lose_every_confirmation)
    response = client.post("/v1/admissions", json=payload)
    assert response.status_code == 503 and "hidden" not in response.text
    assert len(commits) >= 2
    with store.sessions() as db:
        row = db.query(Entry).one()
        assert row.accepted_at.isoformat() in first["acceptedAt"]
        assert row.expires_at.isoformat() in first["expiresAt"]
    assert setup[4] == []


@pytest.mark.parametrize("severity", ["WARNING", "NOTICE", None])
def test_postgresql_commit_warning_is_not_confirmation(admission, severity):
    from types import SimpleNamespace

    store, _, _, _, _ = admission
    handlers = []
    driver = SimpleNamespace(add_notice_handler=handlers.append, remove_notice_handler=handlers.remove)
    connection = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"),
                                 connection=SimpleNamespace(driver_connection=driver))

    def commit():
        if severity:
            handlers[0](SimpleNamespace(severity_nonlocalized=severity, message_primary="hidden sensitive notice"))

    statements = []
    db = SimpleNamespace(connection=lambda: connection, commit=commit, execute=lambda sql: statements.append(str(sql)))
    if severity == "WARNING":
        with pytest.raises(exc.OperationalError) as error:
            store.confirm_commit(db, None)
        assert retryable_admission_error(error.value)
        assert "hidden" not in str(error.value)
    else:
        store.confirm_commit(db, None)
    assert handlers == []
    assert statements == ["SET LOCAL client_min_messages = 'warning'"]


def test_commit_notice_handler_is_removed_when_commit_raises(admission):
    from types import SimpleNamespace

    store, _, _, _, _ = admission
    handlers = []
    driver = SimpleNamespace(add_notice_handler=handlers.append, remove_notice_handler=handlers.remove)
    connection = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"),
                                 connection=SimpleNamespace(driver_connection=driver))

    def fail_commit():
        raise psycopg.OperationalError("controlled transport failure")

    with pytest.raises(psycopg.OperationalError):
        store.confirm_commit(SimpleNamespace(connection=lambda: connection, commit=fail_commit,
                                             execute=lambda _sql: None), None)
    assert handlers == []


def test_request_hooks_are_removed_before_connection_returns_to_pool(admission, monkeypatch):
    from sqlalchemy import event

    store, client, payload, _, _ = admission
    original = store.authenticate
    connections, checked = [], []

    def authenticate(db, *args, **kwargs):
        connections.append(db.connection())
        return original(db, *args, **kwargs)

    def on_checkin(*_args):
        for connection in connections:
            assert not list(connection.dispatch.before_cursor_execute)
            assert not list(connection.dispatch.commit)
            checked.append(connection)

    monkeypatch.setattr(store, "authenticate", authenticate)
    event.listen(store.engine, "checkin", on_checkin)
    try:
        assert client.post("/v1/admissions", json=payload).status_code == 202
        assert len(checked) == 1
    finally:
        event.remove(store.engine, "checkin", on_checkin)


@pytest.mark.parametrize("method", ["post", "get"])
def test_transient_connection_recovers_in_new_authenticated_session(admission, monkeypatch, method):
    store, client, payload, _, setup = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202
    original = store.authenticate
    attempts = []

    def authenticate(db, *args, **kwargs):
        attempts.append(db)
        if len(attempts) == 1:
            raise exc.OperationalError("hidden", {}, psycopg.OperationalError("hidden"))
        return original(db, *args, **kwargs)

    monkeypatch.setattr(store, "authenticate", authenticate)
    response = (client.post("/v1/admissions", json=payload) if method == "post"
                else client.get("/v1/admissions/" + payload["requestId"]))
    assert response.status_code == (202 if method == "post" else 200)
    assert len(attempts) == 2 and attempts[0] is not attempts[1]
    assert setup[4] == []


@pytest.mark.parametrize("mutation", ["revoke", "expire"])
def test_recovery_reauthenticates_revocation_and_expiry(admission, monkeypatch, mutation):
    store, client, payload, grant_id, _ = admission
    original = store.authenticate
    attempts = []

    def authenticate(db, *args, **kwargs):
        attempts.append(db)
        if len(attempts) == 1:
            with store.sessions() as local:
                grant = local.get(Grant, grant_id)
                if mutation == "revoke":
                    grant.revoked_at = now()
                else:
                    grant.expires_at = now() - timedelta(seconds=1)
                local.commit()
            raise exc.OperationalError("hidden", {}, psycopg.OperationalError("hidden"))
        return original(db, *args, **kwargs)

    monkeypatch.setattr(store, "authenticate", authenticate)
    assert client.post("/v1/admissions", json=payload).status_code == 401
    assert len(attempts) == 2
    with store.sessions() as db:
        assert db.query(Entry).count() == 0


@pytest.mark.parametrize("phase", ["query", "commit"])
def test_timeout_stops_late_sql_or_commit_and_does_not_retry(admission, monkeypatch, phase):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    import time

    store, client, payload, _, _ = admission
    entered, release, finished = Event(), Event(), Event()
    calls = []
    original = store.authenticate if phase == "query" else store.sessions.class_.commit

    def wait_then_continue(*args, **kwargs):
        calls.append(1)
        entered.set()
        try:
            assert release.wait(3)
            return original(*args, **kwargs)
        finally:
            finished.set()

    if phase == "query":
        monkeypatch.setattr(store, "authenticate", wait_then_continue)
    else:
        monkeypatch.setattr(store.sessions.class_, "commit", wait_then_continue)
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(client.post, "/v1/admissions", json=payload)
        assert entered.wait(1)
        try:
            assert response.result(timeout=2).status_code == 503
            assert time.monotonic() - started < 2
        finally:
            release.set()
        assert finished.wait(1)
    assert len(calls) == 1
    with store.sessions() as db:
        assert db.query(Entry).count() == 0


def test_timeout_during_started_commit_does_not_claim_it_was_rolled_back(admission, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    store, client, payload, _, setup = admission
    committed, release, finished = Event(), Event(), Event()
    original = store.sessions.class_.commit

    def commit_then_lose_reply(self):
        original(self)
        committed.set()
        try:
            assert release.wait(3)
        finally:
            finished.set()

    monkeypatch.setattr(store.sessions.class_, "commit", commit_then_lose_reply)
    with ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(client.post, "/v1/admissions", json=payload)
        assert committed.wait(1)
        try:
            assert response.result(timeout=2).status_code == 503
        finally:
            release.set()
        assert finished.wait(1)
    assert client.get("/v1/admissions/" + payload["requestId"]).json()["accepted"]
    with store.sessions() as db:
        assert db.query(Entry).count() == 1
    assert setup[4] == []


async def test_client_disconnect_stops_waiting_and_prevents_later_commit(admission, monkeypatch):
    import asyncio
    import json
    from threading import Event

    store, client, payload, _, _ = admission
    entered, release, finished = Event(), Event(), Event()
    original = store.sessions.class_.commit

    def delayed_commit(self):
        entered.set()
        try:
            assert release.wait(3)
            return original(self)
        finally:
            finished.set()

    monkeypatch.setattr(store.sessions.class_, "commit", delayed_commit)
    body_sent = False

    async def receive():
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": json.dumps(payload).encode(), "more_body": False}
        while not entered.is_set():
            await asyncio.sleep(0.01)
        return {"type": "http.disconnect"}

    sent = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/v1/admissions", "raw_path": b"/v1/admissions",
        "query_string": b"", "root_path": "", "server": ("test", 80), "client": ("test", 1234),
        "headers": [(b"x-agentops-admission-key", client.headers["X-AgentOps-Admission-Key"].encode())]}
    try:
        await asyncio.wait_for(create_app(store.settings, store=store)(scope, receive, send), timeout=0.8)
        assert entered.is_set()
        assert not any(message.get("status") == 202 for message in sent)
    finally:
        release.set()
    for _ in range(100):
        if finished.is_set():
            break
        await asyncio.sleep(0.01)
    assert finished.is_set()
    with store.sessions() as db:
        assert db.query(Entry).count() == 0


@pytest.mark.parametrize("code, expected", [
    ("08006", True), ("25006", True), ("57P03", True), ("55P03", True), ("57014", True),
    ("28P01", False), ("23505", False), ("42601", False), ("53300", False),
])
def test_admission_retries_only_explicit_transient_errors(code, expected):
    error = exc.OperationalError("hidden", {}, psycopg.errors.lookup(code)("hidden"))
    assert retryable_admission_error(error) is expected
    assert retryable_admission_error(exc.TimeoutError())
    assert not retryable_admission_error(ValueError("not a DB failure"))


def test_database_authentication_error_is_not_retried(admission, monkeypatch):
    store, client, payload, _, _ = admission
    calls = []

    def fail(*_args, **_kwargs):
        calls.append(1)
        raise exc.OperationalError("hidden", {}, psycopg.errors.InvalidPassword("hidden"))

    monkeypatch.setattr(store, "authenticate", fail)
    with pytest.raises(exc.OperationalError):
        client.post("/v1/admissions", json=payload)
    assert len(calls) == 1


@pytest.mark.parametrize("status", [401, 403, 409, 429])
def test_authority_conflict_and_capacity_responses_are_not_retried(admission, monkeypatch, status):
    from fastapi import HTTPException

    store, client, payload, _, _ = admission
    calls = []

    def fail(*_args, **_kwargs):
        calls.append(1)
        raise HTTPException(status, "controlled rejection")

    monkeypatch.setattr(store, "accept", fail)
    assert client.post("/v1/admissions", json=payload).status_code == status
    assert len(calls) == 1


def test_swapped_encrypted_payload_never_imports(admission):
    store, client, payload, _, setup = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202
    assert client.post("/v1/admissions", json={**payload, "requestId": str(uuid4())}).status_code == 202
    with store.sessions() as db:
        first, second = db.query(Entry).order_by(Entry.accepted_at).all()
        first.encrypted_payload = second.encrypted_payload
        db.commit()
    assert handoff(store, SessionLocal, store.claim())
    result = client.get("/v1/admissions/" + payload["requestId"]).json()
    assert result["state"] == "rejected" and result["reason"] == "payload_binding_failed"
    with SessionLocal() as db:
        assert db.query(ToolInvocation).filter_by(project_id=setup[0]).count() == 0


@pytest.mark.parametrize("mutation", ["revoke", "policy", "tool"])
def test_current_execution_authority_is_rechecked(admission, mutation):
    store, client, payload, _, setup = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202
    with SessionLocal() as db:
        if mutation == "revoke":
            db.query(ApiKey).filter_by(project_id=setup[0]).one().revoked_at = now()
        else:
            policy = db.get(ToolExecutionPolicy, setup[1] + ":demo.echo")
            if mutation == "policy":
                policy.evidence_sha256 = "c" * 64
            else:
                policy.queue_enabled = False
        db.commit()
    assert handoff(store, SessionLocal, store.claim())
    assert client.get("/v1/admissions/" + payload["requestId"]).json()["state"] == "rejected"
    with SessionLocal() as db:
        assert db.query(ToolInvocation).filter_by(project_id=setup[0]).count() == 0
    assert setup[4] == []


def test_admission_credential_is_separate_and_revocation_is_immediate(admission):
    store, client, payload, grant_id, setup = admission
    response = client.post("/v1/admissions", headers={"X-AgentOps-Admission-Key": ""}, json=payload)
    assert response.status_code == 401
    assert client.post("/v1/admissions", json={**payload, "name": "unreviewed"}).status_code == 403
    assert client.post("/v1/admissions", json=payload).status_code == 202
    with store.sessions() as db:
        db.get(Grant, grant_id).revoked_at = now()
        db.commit()
    assert client.get("/v1/admissions/" + payload["requestId"]).status_code == 401
    assert client.post("/v1/admissions", json=payload).status_code == 401
    # Revocation of the deposit credential is not cancellation of accepted work.
    assert handoff(store, SessionLocal, store.claim())


def test_size_schema_capacity_expiry_and_no_unconfirmed_202(admission, monkeypatch):
    store, client, payload, _, _ = admission
    assert client.post("/v1/admissions", json={**payload, "url": "http://other"}).status_code == 400
    assert client.post("/v1/admissions", json={**payload, "arguments": {
        "text": "admission_" + "x" * 40}}).status_code == 400
    assert client.post("/v1/admissions", json={**payload, "arguments": {"text": "x" * 65536}}).status_code == 413
    assert client.post("/v1/admissions", json=payload).status_code == 202
    monkeypatch.setattr(store.settings, "max_pending_per_grant", 1)
    assert client.post("/v1/admissions", json={**payload, "requestId": str(uuid4())}).status_code == 429
    with store.sessions() as db:
        db.query(Entry).one().expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert handoff(store, SessionLocal, store.claim())
    assert client.get("/v1/admissions/" + payload["requestId"]).json()["state"] == "expired"

    def failed_commit(self):
        raise exc.OperationalError("hidden", {}, psycopg.OperationalError("hidden"))

    monkeypatch.setattr(store.sessions.class_, "commit", failed_commit)
    response = client.post("/v1/admissions", json={**payload, "requestId": str(uuid4())})
    assert response.status_code == 503 and "hidden" not in response.text


def test_default_disabled_and_safe_storage_settings(admission):
    store, _, _, _, _ = admission
    store.settings.enabled = False
    with TestClient(create_app(store.settings, store=store)) as client:
        assert client.get("/readyz").status_code == 503
    with pytest.raises(ValueError):
        AdmissionSettings(database_url="sqlite://", encryption_key=Fernet.generate_key().decode())
    values = store.settings.model_dump(exclude={"request_timeout_seconds"})
    assert AdmissionSettings(**values).request_timeout_seconds == 8
    for value in (0, 46):
        with pytest.raises(ValueError):
            AdmissionSettings(**values, request_timeout_seconds=value)


def test_http_imports_do_not_initialize_business_database():
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-c", "\n".join([
        "import sys",
        "from agentops_guard.admission.app import create_app",
        "from agentops_guard.backend.services.content import detect_secret_labels",
        "assert not detect_secret_labels('ordinary text')",
        "assert 'agentops_guard.backend.database' not in sys.modules",
    ])], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_expired_importer_cannot_overwrite_new_owner(admission):
    store, client, payload, _, _ = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202
    old_claim = store.claim()
    force_due(store)
    new_claim = store.claim()
    assert new_claim[1] != old_claim[1]
    assert not store.finish(old_claim, state="rejected")
    assert not handoff(store, SessionLocal, old_claim)
    assert handoff(store, SessionLocal, new_claim)
    assert client.get("/v1/admissions/" + payload["requestId"]).json()["state"] == "imported"


def test_other_actor_cannot_read_or_adopt_existing_request(admission):
    from test_gateway import create_agent_headers

    store, client, payload, _, setup = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202
    create_agent_headers(setup[0], "another-agent")
    with SessionLocal() as db:
        key = db.query(ApiKey).filter_by(project_id=setup[0], agent_id="another-agent").one()
        _, other_token = provision(store, db, key_id=key.id, tool_ids=[setup[1] + ":demo.echo"])
    other_headers = {"X-AgentOps-Admission-Key": other_token}
    assert client.get("/v1/admissions/" + payload["requestId"], headers=other_headers).status_code == 404
    assert client.post("/v1/admissions", headers=other_headers, json=payload).status_code == 202
    with store.sessions() as db:
        assert db.query(Entry).count() == 2


def test_conflicting_direct_business_request_does_not_become_our_success(admission):
    from test_gateway import client as gateway_client
    store, client, payload, _, setup = admission
    assert client.post("/v1/admissions", json=payload).status_code == 202
    other = {**payload, "arguments": {"text": "different direct request"}}
    assert gateway_client.post("/mcp/invocations", headers=setup[2], json=other).status_code == 202
    assert handoff(store, SessionLocal, store.claim())
    result = client.get("/v1/admissions/" + payload["requestId"]).json()
    assert result["state"] == "rejected" and result["reason"] == "business_request_conflict"
    assert setup[4] == []


def test_accepted_work_does_not_bypass_later_approval(admission):
    from test_gateway import backend_client, backend_headers
    from agentops_guard.backend.services import tool_invocations as inv
    from agentops_guard.backend.models import McpTool
    store, client, payload, _, setup = admission
    # A separately operator-reviewed write is still subject to the existing
    # original-intent/approval gate. The admission grant is not an approval.
    with SessionLocal() as db:
        tool = db.get(McpTool, setup[1] + ":demo.echo")
        tool.input_schema = {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}
        tool.name = "write_file"
        tool.id = setup[1] + ":write_file"
        db.flush()
        revision = inv.current_revision(db, setup[0], tool.id)
        digest = revision.content_digest
        db.commit()
    response = backend_client.put(f"/v1/mcp/tools/{setup[1]}:write_file/execution-policy", headers=backend_headers,
        json={"project_id": setup[0], "revision_digest": digest, "queue_enabled": True,
              "retry_mode": "never", "evidence_sha256": "c" * 64})
    assert response.status_code == 200
    with store.sessions() as local, SessionLocal() as business:
        grant = local.query(Grant).one()
        from agentops_guard.backend.models import ToolExecutionPolicy
        policy = business.get(ToolExecutionPolicy, setup[1] + ":write_file")
        grant.tools = {policy.tool_id: {"revision": digest, "policy": inv._digest(inv._policy_value(policy))}}
        local.commit()
    payload = {**payload, "name": "write_file", "arguments": {"path": "/controlled/probe.txt", "content": "ordinary"}}
    assert client.post("/v1/admissions", json=payload).status_code == 202
    assert handoff(store, SessionLocal, store.claim())
    with SessionLocal() as db:
        job_id = db.query(ToolInvocation).filter_by(project_id=setup[0]).one().job_id
    assert jobs.execute_job(job_id)["state"] == "waiting_approval"
    assert setup[4] == []
