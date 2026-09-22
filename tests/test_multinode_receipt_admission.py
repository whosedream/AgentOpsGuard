"""The cluster seed's reviewed result contract through real independent MCP.

Local SQLite admission/business stores are a functional test, not HA evidence.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid4, uuid5

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest

from test_gateway import client as gateway_client
from test_independent_admission import force_due
from test_tool_receipts_runtime import durable_downstream as durable_downstream
from agentops_guard.admission.app import create_app
from agentops_guard.admission.importer import handoff
from agentops_guard.admission.store import AdmissionSettings, Grant, Store
from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import McpTool, ToolExecutionPolicy, ToolInvocation
from agentops_guard.backend.services import jobs, scanner_rule_packs, tool_invocations, tool_receipts
from agentops_guard.gateway import app as gateway
from agentops_guard.gateway.transports.streamable_http import StreamableHttpTransport


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("multinode_receipt_runtime", ROOT / "evals/multinode-runtime/runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


@pytest.fixture
def seeded_admission(monkeypatch, tmp_path):
    settings = AdmissionSettings(enabled=True, allow_test_sqlite=True,
        database_url=f"sqlite:///{tmp_path / 'separate-admission.db'}", encryption_key=Fernet.generate_key().decode())
    store = Store(settings)
    store.initialize()
    import agentops_guard.admission.store as store_module

    monkeypatch.setattr(store_module, "AdmissionSettings", lambda: settings)
    monkeypatch.setattr(runtime, "tables", lambda: None)  # PostgreSQL-only measurement tables are not this test's subject.
    monkeypatch.setattr(runtime, "RECEIPT_FIXTURE_PATH", ROOT / "tests/fixtures/receipt_mcp_server.py")
    monkeypatch.setattr(scanner_rule_packs, "install_scanner_rule_pack", lambda *args, **kwargs: None)
    monkeypatch.setattr(get_settings(), "invocation_encryption_key", SecretStr(Fernet.generate_key().decode()))
    monkeypatch.setattr(get_settings(), "semantic_scanner_mode", "disabled")

    @contextmanager
    def make(*, result_recovery=True, url=None):
        if url is not None:
            monkeypatch.setattr(runtime, "RECEIPT_FIXTURE_URL", url)
        phase = "mn_" + uuid4().hex[:12]
        seed = runtime.seed_admission({"phase": phase, "result_recovery": result_recovery})
        client = TestClient(create_app(settings, store=store), headers={"X-AgentOps-Admission-Key": seed["admission_token"]})
        try:
            yield phase, seed, store, client
        finally:
            client.close()

    try:
        yield make
    finally:
        store.engine.dispose()


@pytest.mark.parametrize("enabled", [False, True])
def test_seed_grants_only_reviewed_action_and_keeps_writes_approval_gated(seeded_admission, enabled):
    with seeded_admission(result_recovery=enabled) as (phase, seed, store, _client):
        assert seed["read_tool"] == ("read_status_v2" if enabled else "read_status")
        assert seed["read_server_id"] == phase + ("_receipts" if enabled else "_upstream")
        read_id, write_id = seed["read_server_id"] + ":" + seed["read_tool"], seed["server_id"] + ":write_file"
        with store.sessions() as db:
            grant = db.get(Grant, seed["grant_id"])
            assert set(grant.tools) == {read_id, write_id}
            pinned = dict(grant.tools)
        with SessionLocal() as db:
            read, write = db.get(ToolExecutionPolicy, read_id), db.get(ToolExecutionPolicy, write_id)
            assert write.receipt_contract is None and write.retry_mode == read.retry_mode == "never"
            for policy in (read, write):
                assert policy.updated_by == "controlled-eval-admin" and policy.queue_enabled
                assert pinned[policy.tool_id]["revision"] == policy.revision_digest
                assert pinned[policy.tool_id]["policy"] == tool_invocations._digest(tool_invocations._policy_value(policy))
            if enabled:
                contract = tool_receipts.ReceiptContract.model_validate(read.receipt_contract)
                tool_receipts.validate_contract(db, phase, read_id, contract)
                assert contract.protocol == "agentops-receipt-v2" and contract.max_result_bytes == 65536
                assert contract.result_revision_digest == tool_invocations.current_revision(db, phase, contract.result_tool_id).content_digest
                assert contract.lookup_revision_digest == tool_invocations.current_revision(db, phase, contract.lookup_tool_id).content_digest
            else:
                assert read.receipt_contract is None


def test_full_admission_commit_loss_queries_original_and_rechecks_scanned_result(
    seeded_admission, durable_downstream, monkeypatch
):
    url, ledger, process, restart = durable_downstream
    calls, scans = [], []
    original_scan = gateway.scan_content

    def real_call(server, name, arguments):
        calls.append((name, dict(arguments)))
        try:
            return StreamableHttpTransport(server.url, timeout=2).call_tool(name, arguments)
        except gateway.UpstreamTransportError as error:
            return {"isError": True, "upstreamError": {"code": error.code}}

    def observed_scan(request, db):
        scans.append((runtime.request_context.get(), request.project_id, request.source))
        return original_scan(request, db)

    monkeypatch.setattr(gateway, "_call_upstream_tool", real_call)
    monkeypatch.setattr(gateway, "scan_content", observed_scan)
    monkeypatch.setattr(tool_receipts, "reconcile_receipt", runtime.receipt_measurement(tool_receipts.reconcile_receipt))
    with seeded_admission(url=url) as (phase, seed, store, client):
        external_id = phase + ":0"
        request_id = str(uuid5(NAMESPACE_URL, "agentops-independent:" + external_id))
        payload = {"requestId": request_id, "serverId": seed["read_server_id"], "name": seed["read_tool"],
            "arguments": {"request_id": external_id, "variant": "short", "crash_after_commit": True}}
        assert client.post("/v1/admissions", json=payload).status_code == 202
        assert handoff(store, SessionLocal, store.claim())
        with SessionLocal() as db:
            row = db.query(ToolInvocation).filter_by(project_id=phase, request_id=request_id).one()
            job_id = row.job_id
        assert jobs.execute_job(job_id)["state"] == "outcome_unknown"
        assert process.wait(timeout=5) == 71
        with SessionLocal() as db:
            row = db.query(ToolInvocation).filter_by(project_id=phase, request_id=request_id).one()
            operation_id = row.receipt_binding["operation_id"]
            assert row.attempts == 1 and row.encrypted_result is None
        with sqlite3.connect(ledger) as db:
            saved = db.execute("SELECT e.request_id,e.phase,e.operation_id,e.executions,e.result_hash,r.result,f.value "
                "FROM eval_tool_receipts e JOIN results_v2 r USING(operation_id) JOIN effects f USING(operation_id)").fetchone()
            assert saved[:4] == (external_id, phase, operation_id, 1)
            assert saved[4] == sha256(saved[5].encode()).hexdigest()
            assert json.loads(saved[5])["content"][0]["text"] == saved[6] == "Service status is healthy."
        # An HTTP duplicate may re-read the receipt but cannot replay the action.
        assert client.post("/v1/admissions", json=payload).status_code == 202
        restart()
        with SessionLocal() as db:
            row = db.query(ToolInvocation).filter_by(project_id=phase, request_id=request_id).one()
            assert tool_receipts.reconcile_receipt(db, row)["state"] == "succeeded"
            assert row.summary["resultScanned"] and row.encrypted_result and row.attempts == 1
        assert (request_id, phase, "mcp_tool_result") in scans
        assert runtime.request_context.get() is None
        force_due(store)
        assert handoff(store, SessionLocal, store.claim())
        status = client.get("/v1/admissions/" + request_id).json()
        assert status["state"] == "completed" and status["businessState"] == "succeeded"
        result = gateway_client.get("/mcp/invocations/" + request_id + "/result",
                                    headers={"X-AgentOps-Api-Key": seed["token"]})
        assert result.status_code == 200
        assert result.json()["content"][0]["text"] == "Service status is healthy."
        assert result.json()["provenance"]
        assert [name for name, _ in calls] == ["read_status_v2", "lookup_receipt_v2", "lookup_result_v2"]
        assert calls[1][1] == calls[2][1] == {"operation_id": operation_id}
        with sqlite3.connect(ledger) as db:
            assert db.execute("SELECT executions FROM eval_tool_receipts").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM effects").fetchone()[0] == 1


def test_all_nine_write_positions_remain_waiting_for_approval(seeded_admission, monkeypatch):
    calls = []
    monkeypatch.setattr(gateway, "_call_upstream_tool", lambda *args: calls.append(args))
    with seeded_admission() as (phase, seed, store, client):
        for index in range(19, 180, 20):
            payload = {"requestId": str(uuid4()), "serverId": seed["server_id"], "name": "write_file",
                "arguments": {"request_id": f"{phase}:{index}", "path": "/controlled/probe.txt", "content": "controlled probe"}}
            assert client.post("/v1/admissions", json=payload).status_code == 202
        for _ in range(9):
            assert handoff(store, SessionLocal, store.claim())
        with SessionLocal() as db:
            job_ids = [row.job_id for row in db.query(ToolInvocation).filter_by(project_id=phase)]
        assert len(job_ids) == 9
        for job_id in job_ids:
            assert jobs.execute_job(job_id)["state"] == "waiting_approval"
        assert calls == []


def test_recovery_context_is_per_thread_and_reset_on_error():
    def observation(_db, row):
        assert runtime.request_context.get() == row.request_id
        if row.request_id == "broken":
            raise ValueError("controlled observer error")
        return runtime.request_context.get()

    measured = runtime.receipt_measurement(observation)
    identifiers = [str(uuid4()) for _ in range(12)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda key: measured(None, SimpleNamespace(request_id=key)), identifiers)) == identifiers
    with pytest.raises(ValueError, match="controlled observer"):
        measured(None, SimpleNamespace(request_id="broken"))
    assert runtime.request_context.get() is None


def test_stale_result_tool_review_is_rejected_before_dispatch(seeded_admission):
    with seeded_admission() as (phase, seed, store, client):
        payload = {"requestId": str(uuid4()), "serverId": seed["read_server_id"], "name": seed["read_tool"],
            "arguments": {"request_id": phase + ":0", "variant": "short"}}
        assert client.post("/v1/admissions", json=payload).status_code == 202
        with SessionLocal() as db:
            tool = db.get(McpTool, seed["read_server_id"] + ":lookup_result_v2")
            tool.description = "changed after operator review"
            db.commit()
        assert handoff(store, SessionLocal, store.claim())
        with SessionLocal() as db:
            row = db.query(ToolInvocation).filter_by(project_id=phase).one()
            assert jobs.execute_job(row.job_id)["state"] == "failed"
        # Registration can be durable; executor must refuse the changed lookup
        # contract before dispatch, rather than trusting the stored grant alone.
