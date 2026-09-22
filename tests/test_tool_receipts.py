"""Receipt contract, isolation and no-replay regression tests."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException

from test_tool_invocations import setup_invocation as setup_invocation, status, enqueue
from test_gateway import client, backend_client, backend_headers, create_agent_headers
from test_tool_recovery import delivery_db as delivery_db
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import ApiKey, McpTool, McpServer, ToolInvocation, ToolExecutionPolicy
from agentops_guard.backend.services import tool_invocations as inv, tool_receipts as receipts, jobs
from agentops_guard.gateway import app as gateway


def configure(setup, *, contract_override=None):
    project, server, *_ = setup
    with SessionLocal() as db:
        tool = db.get(McpTool, server + ":demo.echo")
        tool.id, tool.name = server + ":echo", "echo"
        setup[3]["name"] = "echo"
        tool.input_schema = {"type": "object", "properties": {
            "text": {"type": "string"}, "operation_id": {"type": "string"}}}
        lookup = McpTool(id=server + ":lookup_receipt", project_id=project, server_id=server,
            name="lookup_receipt", description="Query the receipt, never execute the action",
            status="active", annotations={}, input_schema={"type": "object",
                "properties": {"operation_id": {"type": "string"}}, "required": ["operation_id"]})
        db.add(lookup)
        db.flush()
        revision = inv.current_revision(db, project, tool.id)
        lookup_revision = inv.current_revision(db, project, lookup.id)
        payload = {"project_id": project, "revision_digest": revision.content_digest,
            "queue_enabled": True, "retry_mode": "never", "evidence_sha256": "b" * 64,
            "receipt_contract": {"key_argument": "operation_id", "lookup_tool_id": lookup.id,
                "lookup_revision_digest": lookup_revision.content_digest, "retention_seconds": 3600}}
        db.commit()
    if contract_override:
        payload["receipt_contract"].update(contract_override)
    return backend_client.put(f"/v1/mcp/tools/{server}:echo/execution-policy",
                              headers=backend_headers, json=payload)


def lose_response(setup, monkeypatch, *, receipt_state="completed"):
    project, server, headers, payload, calls = setup
    assert configure(setup).status_code == 200
    observed = {}

    def downstream(_server, name, arguments):
        calls.append((name, dict(arguments)))
        if name == "echo":
            observed.update(operation_id=arguments["operation_id"], tool=name,
                            state=receipt_state, result_sha256="a" * 64)
            raise RuntimeError("loss after downstream commit")
        assert name == "lookup_receipt" and arguments == {"operation_id": calls[0][1]["operation_id"]}
        return {"isError": False, "structuredContent": dict(observed)}

    monkeypatch.setattr(gateway, "_call_upstream_tool", downstream)
    with pytest.raises(RuntimeError, match="loss after downstream commit"):
        client.post("/mcp/tools/call", headers=headers, json=payload)
    with SessionLocal() as db:
        row = db.query(ToolInvocation).filter_by(project_id=project).one()
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        inv.reconcile_invocations(db)
        db.commit()
    return observed


def reconcile(setup, **kwargs):
    return client.post("/mcp/invocations/" + setup[3]["requestId"] + "/reconcile",
                       headers=setup[2], **kwargs)


def test_confirms_only_business_outcome_not_scanned_output(setup_invocation, monkeypatch):
    setup = setup_invocation
    lose_response(setup, monkeypatch)
    response = reconcile(setup)
    assert response.status_code == 200
    data = response.json()
    assert data["state"] == "execution_confirmed" and data["attempts"] == 1
    assert not data["resultStored"] and not data["clientMayReplay"]
    assert data["summary"]["businessExecutionConfirmed"]
    assert not data["summary"]["resultAvailable"] and not data["summary"]["resultScanned"]
    assert "content" not in data
    assert reconcile(setup).json() == data
    client.post("/mcp/tools/call", headers=setup[2], json=setup[3])
    assert [call[0] for call in setup[4]] == ["echo", "lookup_receipt"]


@pytest.mark.parametrize("state", ["not_found", "pending"])
def test_missing_or_pending_never_replays(setup_invocation, monkeypatch, state):
    lose_response(setup_invocation, monkeypatch, receipt_state=state)
    assert reconcile(setup_invocation).json()["state"] == "outcome_unknown"
    assert [call[0] for call in setup_invocation[4]] == ["echo", "lookup_receipt"]


@pytest.mark.parametrize("field,value", [("operation_id", "0" * 64), ("tool", "other"),
    ("result_sha256", None), ("state", "untrusted prose"), ("extra", "raw secret"),
    ("result_sha256", "not-a-hash")])
def test_mismatched_or_untrusted_receipt_does_not_confirm(setup_invocation, monkeypatch, field, value):
    receipt = lose_response(setup_invocation, monkeypatch)
    receipt[field] = value
    assert reconcile(setup_invocation).status_code == 502
    assert status(setup_invocation)["state"] == "outcome_unknown"


@pytest.mark.parametrize("mutation", ["policy", "lookup", "destination", "revoke", "agents", "retention"])
def test_changed_review_authority_or_window_blocks_query(setup_invocation, monkeypatch, mutation):
    lose_response(setup_invocation, monkeypatch)
    project, server, *_ = setup_invocation
    with SessionLocal() as db:
        row = db.query(ToolInvocation).filter_by(project_id=project).one()
        if mutation == "policy":
            db.get(ToolExecutionPolicy, row.tool_id).evidence_sha256 = "c" * 64
        elif mutation == "lookup":
            db.get(McpTool, server + ":lookup_receipt").description = "changed tool"
        elif mutation == "destination":
            db.get(McpServer, server).url = "http://other.invalid/mcp"
        elif mutation == "revoke":
            db.get(ApiKey, row.subject["actor_id"]).revoked_at = datetime.now(UTC)
        elif mutation == "agents":
            db.get(McpServer, server).allowed_agents = ["another-agent"]
        else:
            row.created_at = datetime.now(UTC) - timedelta(hours=2)
        db.commit()
    assert reconcile(setup_invocation).status_code in {401, 403, 409}
    assert [call[0] for call in setup_invocation[4]] == ["echo"]


def test_other_actor_cannot_query_receipt(setup_invocation, monkeypatch):
    lose_response(setup_invocation, monkeypatch)
    headers = create_agent_headers(setup_invocation[0], "another-actor")
    response = client.post("/mcp/invocations/" + setup_invocation[3]["requestId"] + "/reconcile",
                           headers=headers)
    assert response.status_code == 404 and len(setup_invocation[4]) == 1


def test_no_review_or_client_supplied_key_cannot_grant_query(setup_invocation):
    assert configure(setup_invocation).status_code == 200
    payload = {**setup_invocation[3], "arguments": {"text": "hi", "operation_id": "a" * 64}}
    response = client.post("/mcp/tools/call", headers=setup_invocation[2], json=payload)
    assert response.status_code == 400 and not setup_invocation[4]


def test_unknown_without_contract_cannot_query(setup_invocation, monkeypatch):
    lose_response(setup_invocation, monkeypatch, receipt_state="not_found")
    with SessionLocal() as db:
        row = db.query(ToolInvocation).filter_by(project_id=setup_invocation[0]).one()
        row.receipt_binding = None
        db.commit()
        with pytest.raises(HTTPException) as exc:
            receipts.reconcile_receipt(db, row)
        assert exc.value.status_code == 409


def test_queue_executes_with_injected_key_after_review(setup_invocation):
    assert configure(setup_invocation).status_code == 200
    _, job_id = enqueue(setup_invocation)
    assert jobs.execute_job(job_id)["state"] == "succeeded"
    assert len(setup_invocation[4][0][1]["operation_id"]) == 64


def test_background_batch_queries_original_receipt(setup_invocation, monkeypatch):
    lose_response(setup_invocation, monkeypatch)
    actual = receipts.reconcile_receipt
    monkeypatch.setattr(receipts, "reconcile_receipt", lambda db, row:
        actual(db, row) if row.project_id == setup_invocation[0] else inv.public_status(row))
    with SessionLocal() as db:
        counts, _ = receipts.reconcile_batch(db, limit=1000)
        assert counts["confirmed"] >= 1
    assert status(setup_invocation)["state"] == "execution_confirmed"
    assert [call[0] for call in setup_invocation[4]] == ["echo", "lookup_receipt"]


def test_batch_cursor_does_not_starve_later_unknown_records(delivery_db, monkeypatch):
    db, queried = delivery_db, []
    for number in range(3):
        db.add(ToolInvocation(id=f"inv_{number}", project_id="cursor", request_id=str(uuid4()),
            actor_digest="a" * 64, subject={}, payload_digest="b" * 64,
            tool_id="test:echo", mode="sync", status="outcome_unknown", attempts=1,
            expires_at=datetime.now(UTC) + timedelta(hours=1), receipt_binding={"test": True}))
    db.commit()
    monkeypatch.setattr(receipts, "reconcile_receipt", lambda _db, row:
        queried.append(row.id) or {"state": "outcome_unknown"})
    cursor = None
    for _ in range(3):
        counts, cursor = receipts.reconcile_batch(db, after_id=cursor, limit=1)
        assert counts == {"queried": 1, "confirmed": 0, "unresolved": 1}
    counts, cursor = receipts.reconcile_batch(db, after_id=cursor, limit=1)
    assert queried == ["inv_0", "inv_1", "inv_2"] and cursor is None and counts["queried"] == 0


def test_revocation_during_lookup_does_not_confirm(setup_invocation, monkeypatch):
    receipt = lose_response(setup_invocation, monkeypatch)

    def revoked(*_args):
        with SessionLocal() as db:
            row = db.query(ToolInvocation).filter_by(project_id=setup_invocation[0]).one()
            db.get(ApiKey, row.subject["actor_id"]).revoked_at = datetime.now(UTC)
            db.commit()
        return {"structuredContent": receipt}

    monkeypatch.setattr(gateway, "_call_upstream_tool", revoked)
    assert reconcile(setup_invocation).status_code == 403
    with SessionLocal() as db:
        row = db.query(ToolInvocation).filter_by(project_id=setup_invocation[0]).one()
        assert row.status == "outcome_unknown"


def test_unknown_after_transport_timeout_remains_queryable_no_action_retry(setup_invocation, monkeypatch):
    assert configure(setup_invocation).status_code == 200
    monkeypatch.setattr(gateway, "_call_upstream_tool", lambda *a:
        {"isError": True, "upstreamError": {"code": "timeout"}})
    _, job_id = enqueue(setup_invocation)
    result = jobs.execute_job(job_id)
    assert result["state"] == "outcome_unknown" and result["attempts"] == 1
    assert reconcile(setup_invocation).status_code == 502
    assert status(setup_invocation)["state"] == "outcome_unknown"


def test_confirmed_receipt_fences_late_executor_result(setup_invocation, monkeypatch):
    lose_response(setup_invocation, monkeypatch)
    with SessionLocal() as db:
        row = db.query(ToolInvocation).filter_by(project_id=setup_invocation[0]).one()
        row.status, row.lease_token = "dispatched", str(uuid4())
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        old = inv.InvocationAttempt(row, row.lease_token)
        db.commit()
        assert receipts.reconcile_receipt(db, row)["state"] == "execution_confirmed"
        with pytest.raises(HTTPException) as caught:
            inv._finish(db, old, "succeeded", {"late": True})
        assert caught.value.status_code == 409
        db.rollback()
        db.refresh(row)
        assert row.status == "execution_confirmed" and not row.summary["resultAvailable"]
