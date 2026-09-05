import json

from fastapi.testclient import TestClient

from agentops_guard.backend.main import app


client = TestClient(app)
headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_healthz_metrics_and_readyz_contract(monkeypatch):
    from agentops_guard.backend.api import routes_observability as routes

    class HealthyRedis:
        def ping(self):
            return True

    monkeypatch.setattr(routes, "redis_connection", lambda: HealthyRedis())
    assert client.get("/healthz").status_code == 200
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "agentops_api_requests_total" in metrics.text
    assert "agentops_runs_total" in metrics.text
    assert "agentops_policy_decisions_total" in metrics.text
    assert "agentops_approvals_pending" in metrics.text
    assert "agentops_jobs_by_status_total" in metrics.text
    assert "agentops_outbox_events_total" in metrics.text
    assert "agentops_execution_requests_total" in metrics.text
    assert "agentops_job_lease_recoveries_total" in metrics.text
    assert "agentops_job_heartbeat_failures_total" in metrics.text
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert set(ready.json()) >= {"status", "database", "redis", "migration"}
    assert ready.json()["migration"]["status"] in {"ok", "skipped"}


def test_request_id_header_is_returned():
    generated = client.get("/healthz")
    assert generated.headers["X-Request-Id"].startswith("req_")
    supplied = client.get("/healthz", headers={"X-Request-Id": "req_test"})
    assert supplied.headers["X-Request-Id"] == "req_test"


def test_request_log_is_json_structured(capsys):
    response = client.get("/healthz?project_id=ops_log", headers={"X-Request-Id": "req_log_test"})
    assert response.status_code == 200
    output = capsys.readouterr().out
    records = [
        json.loads(line) for line in output.splitlines() if line.startswith("{")
    ]
    assert records
    latest = records[-1]
    assert latest["request_id"] == "req_log_test"
    assert latest["method"] == "GET"
    assert latest["path"] == "/healthz"
    assert latest["status"] == 200
    assert isinstance(latest["duration_ms"], int)
    assert "project_id" not in latest
    assert "ops_log" not in output


def test_readyz_stays_available_with_degraded_redis(monkeypatch):
    from redis.exceptions import ConnectionError

    from agentops_guard.backend.api import routes_observability as routes

    class DownRedis:
        def ping(self):
            raise ConnectionError("down")

    monkeypatch.setattr(routes, "redis_connection", lambda: DownRedis())
    assert client.get("/healthz").status_code == 200
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["redis"]["status"] == "degraded"
    assert ready.json()["redis"]["url"] is None


def test_readyz_returns_503_on_migration_mismatch(monkeypatch):
    from agentops_guard.backend.api import routes_observability as routes
    from agentops_guard.backend.schemas import ComponentStatus

    class HealthyRedis:
        def ping(self):
            return True

    monkeypatch.setattr(routes, "redis_connection", lambda: HealthyRedis())
    monkeypatch.setattr(
        routes,
        "migration_status",
        lambda _db: ComponentStatus(status="error", detail="migration mismatch"),
    )
    ready = client.get("/readyz")
    assert ready.status_code == 503
    assert ready.json()["migration"]["status"] == "error"
    assert "migration mismatch" in ready.json()["migration"]["detail"]


def test_api_key_create_authenticate_revoke_and_audit():
    created = client.post(
        "/v1/api-keys",
        headers=headers,
        json={"project_id": "default", "name": "pytest", "scopes": ["runs:read"]},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["token"].startswith("ag_")

    listed = client.get("/v1/api-keys?project_id=default", headers=headers)
    assert listed.status_code == 200
    assert any(item["id"] == body["id"] for item in listed.json())

    authenticated = client.get("/v1/runs", headers={"X-AgentOps-Api-Key": body["token"]})
    assert authenticated.status_code == 200

    forbidden = client.get("/v1/api-keys", headers={"X-AgentOps-Api-Key": body["token"]})
    assert forbidden.status_code == 403

    revoked = client.delete(f"/v1/api-keys/{body['id']}", headers=headers)
    assert revoked.status_code == 200
    rejected = client.get("/v1/runs", headers={"X-AgentOps-Api-Key": body["token"]})
    assert rejected.status_code == 401

    audit = client.get("/v1/audit-logs?project_id=default", headers=headers)
    assert audit.status_code == 200
    actions = {item["action"] for item in audit.json()}
    assert {"api_key.create", "api_key.revoke"} <= actions


def test_page_mode_envelope_for_runs():
    for index in range(2):
        response = client.post(
            "/v1/runs",
            headers=headers,
            json={"project_id": "default", "name": f"paged {index}"},
        )
        assert response.status_code == 200
    page = client.get("/v1/runs?project_id=default&limit=1&page_mode=envelope", headers=headers)
    assert page.status_code == 200
    body = page.json()
    assert "items" in body
    assert "next_cursor" in body
    assert len(body["items"]) == 1


def test_job_endpoint_commits_to_outbox_without_contacting_redis():
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import OutboxEvent

    run = client.post(
        "/v1/runs", headers=headers, json={"project_id": "default", "name": "replay seed"}
    ).json()
    response = client.post(
        "/v1/replays/jobs",
        headers=headers,
        json={"project_id": "default", "source_run_id": run["id"], "mode": "exact"},
    )
    assert response.status_code == 200
    assert response.json()["rq_job_id"] is None
    db = SessionLocal()
    try:
        event = db.get(OutboxEvent, f"outbox_{response.json()['id']}")
        assert event is not None
        assert event.status == "pending"
    finally:
        db.close()


def test_job_outbox_creation_paths_and_pagination():
    suite = client.post(
        "/v1/eval-suites",
        headers=headers,
        json={"project_id": "default", "name": "jobs", "cases": []},
    ).json()
    eval_job = client.post(f"/v1/eval-suites/{suite['id']}/jobs", headers=headers)
    assert eval_job.status_code == 200
    assert eval_job.json()["rq_job_id"] is None

    server = client.post(
        "/v1/mcp/servers",
        headers=headers,
        json={"id": "job_mcp", "project_id": "default", "name": "job_mcp", "transport": "stdio"},
    )
    assert server.status_code == 200
    refresh_job = client.post("/v1/mcp/servers/job_mcp/refresh", headers=headers)
    assert refresh_job.status_code == 200

    jobs = client.get("/v1/jobs?project_id=default&limit=1&page_mode=envelope", headers=headers)
    assert jobs.status_code == 200
    assert len(jobs.json()["items"]) == 1
    fetched = client.get(f"/v1/jobs/{eval_job.json()['id']}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["kind"] == "eval_run"


def test_page_mode_envelope_for_replays_eval_runs_and_audit():
    replay_page = client.get(
        "/v1/replays?project_id=default&limit=1&page_mode=envelope", headers=headers
    )
    eval_page = client.get(
        "/v1/eval-runs?project_id=default&limit=1&page_mode=envelope", headers=headers
    )
    audit_page = client.get(
        "/v1/audit-logs?project_id=default&limit=1&page_mode=envelope", headers=headers
    )
    assert replay_page.status_code == 200
    assert eval_page.status_code == 200
    assert audit_page.status_code == 200
    assert "items" in replay_page.json()
    assert "items" in eval_page.json()
    assert "items" in audit_page.json()


def test_job_execute_success_and_failure(monkeypatch):
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import BackgroundJob, McpServer, McpTool, OutboxEvent
    from agentops_guard.backend.services import mcp_refresh
    from agentops_guard.backend.services.jobs import create_job, execute_job

    monkeypatch.setattr(
        mcp_refresh,
        "_load_tools_from_server",
        lambda _server, strict=False: [
            {"name": "demo.echo", "description": "safe echo", "inputSchema": {"type": "object"}}
        ],
    )

    db = SessionLocal()
    try:
        db.merge(
            McpServer(
                id="demo", project_id="default", name="demo", transport="stdio", status="active"
            )
        )
        success = create_job(db, "default", "mcp_refresh", {"server_id": "demo"})
        failing = create_job(db, "default", "unknown", {})
        db.commit()
        success_id = success.id
        failing_id = failing.id
    finally:
        db.close()

    assert execute_job(success_id)["status"] == "completed"
    assert execute_job(success_id)["status"] == "completed"
    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, success_id)
        assert row.status == "completed"
        assert row.attempts == 1
        assert db.get(McpTool, "demo:demo.echo") is not None
    finally:
        db.close()

    try:
        execute_job(failing_id)
    except ValueError:
        pass
    else:
        raise AssertionError("unsupported job should fail")
    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, failing_id)
        assert row.status == "pending"
        assert row.error == "job_execution_failed"
        assert row.lease_owner is None
        assert row.lease_expires_at is None
        assert db.get(OutboxEvent, f"outbox_retry_{failing_id}_1") is not None
    finally:
        db.close()
