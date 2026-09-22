"""Real MCP process death after an independently durable business commit."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time

import pytest

from test_tool_invocations import setup_invocation as setup_invocation, status
from test_tool_receipts import configure, reconcile
from test_gateway import client
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import McpServer
from agentops_guard.gateway import app as gateway
from agentops_guard.gateway.transports.streamable_http import StreamableHttpTransport


@pytest.fixture
def durable_downstream(tmp_path):
    path = tmp_path / "independent-downstream.db"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    processes = []

    def start():
        process = subprocess.Popen([sys.executable,
            str(Path(__file__).parent / "fixtures/receipt_mcp_server.py"),
            "--database", str(path), "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert process.poll() is None, "controlled receipt process exited during startup"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    return process
            except OSError:
                time.sleep(.05)
        pytest.fail("controlled receipt process did not start")

    process = start()
    try:
        yield f"http://127.0.0.1:{port}/mcp", path, process, start
    finally:
        for item in processes:
            if item.poll() is None:
                item.terminate()
                try:
                    item.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    item.kill()
                    item.wait(timeout=5)


def test_real_commit_then_process_exit_is_reconciled_without_replay(
    setup_invocation, durable_downstream, monkeypatch
):
    url, ledger, process, restart = durable_downstream
    project, server_id, headers, payload, _ = setup_invocation
    with SessionLocal() as db:
        server = db.get(McpServer, server_id)
        server.transport, server.url = "streamable_http", url
        db.commit()
    assert configure(setup_invocation).status_code == 200
    # Use the real MCP transport, not setup_invocation's unit-test stub.
    def call(server, name, arguments):
        try:
            return StreamableHttpTransport(server.url, timeout=2).call_tool(name, arguments)
        except gateway.UpstreamTransportError as error:
            return {"isError": True, "upstreamError": {"code": error.code}}

    monkeypatch.setattr(gateway, "_call_upstream_tool", call)
    payload["arguments"] = {"text": "synthetic business effect", "crash_after_commit": True}
    response = client.post("/mcp/tools/call", headers=headers, json=payload)
    assert response.status_code == 200
    assert response.json()["invocation"]["state"] == "outcome_unknown"
    assert process.wait(timeout=5) == 71
    with sqlite3.connect(ledger) as db:
        assert db.execute("SELECT count(*) FROM effects").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
    restart()
    result = reconcile(setup_invocation)
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "execution_confirmed"
    assert status(setup_invocation)["attempts"] == 1
    assert not result.json()["summary"]["resultScanned"]
    with sqlite3.connect(ledger) as db:
        assert db.execute("SELECT count(*) FROM effects").fetchone()[0] == 1


def test_real_parallel_duplicate_requests_have_one_effect_and_reject_changed_arguments(durable_downstream):
    url, ledger, *_ = durable_downstream
    key = "a" * 64

    def send(_):
        return StreamableHttpTransport(url, timeout=5).call_tool("echo", {
            "text": "synthetic value", "operation_id": key})

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(send, range(16)))
    assert all(not result.get("isError") for result in responses)
    changed = StreamableHttpTransport(url, timeout=5).call_tool("echo", {
        "text": "changed value", "operation_id": key})
    assert changed["isError"]
    with sqlite3.connect(ledger) as db:
        assert db.execute("SELECT count(*) FROM effects").fetchone()[0] == 1
        assert db.execute("SELECT value FROM effects").fetchone()[0] == "synthetic value"


def test_real_v2_process_exit_recovers_original_scanned_result(
    setup_invocation, durable_downstream, monkeypatch
):
    from test_tool_results import configure_v2, get_result
    from agentops_guard.backend.services.tool_receipts import reconcile_batch

    url, ledger, process, restart = durable_downstream
    project, server_id, headers, payload, calls = setup_invocation
    with SessionLocal() as db:
        server = db.get(McpServer, server_id)
        server.transport, server.url = "streamable_http", url
        db.commit()
    configure_v2(setup_invocation)

    def call(server, name, arguments):
        calls.append(name)
        try:
            return StreamableHttpTransport(server.url, timeout=2).call_tool(name, arguments)
        except gateway.UpstreamTransportError as error:
            return {"isError": True, "upstreamError": {"code": error.code}}

    monkeypatch.setattr(gateway, "_call_upstream_tool", call)
    payload["arguments"] = {"text": "original durable result", "crash_after_commit": True}
    response = client.post("/mcp/tools/call", headers=headers, json=payload)
    assert response.json()["invocation"]["state"] == "outcome_unknown"
    assert process.wait(timeout=5) == 71
    restart()
    # Background worker, not a second submission of the original action.
    with SessionLocal() as db:
        reconcile_batch(db, limit=10000)
    assert status(setup_invocation)["state"] == "succeeded"
    response = get_result(setup_invocation)
    assert response.status_code == 200, response.text
    assert response.json()["content"][0]["text"] == "original durable result"
    assert calls.count("echo_v2") == 1
    with sqlite3.connect(ledger) as db:
        assert db.execute("SELECT count(*) FROM effects").fetchone()[0] == 1


def test_status_v2_concurrent_duplicates_and_conflicts_preserve_one_original_result(durable_downstream):
    from hashlib import sha256
    import json

    url, ledger, *_ = durable_downstream
    arguments = {"request_id": "mn_0123456789ab:7", "variant": "short", "operation_id": "b" * 64}

    def send(_):
        return StreamableHttpTransport(url, timeout=5).call_tool("read_status_v2", arguments)

    with ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(send, range(16)))
    assert all(not reply.get("isError") for reply in replies)
    for changed in ({"variant": "long"}, {"request_id": "mn_0123456789ab:8"}, {"operation_id": "c" * 64}):
        reply = StreamableHttpTransport(url, timeout=5).call_tool("read_status_v2", {**arguments, **changed})
        assert reply["isError"]
    transport = StreamableHttpTransport(url, timeout=5)
    receipt = transport.call_tool("lookup_receipt_v2", {"operation_id": arguments["operation_id"]})["structuredContent"]
    recovered = transport.call_tool("lookup_result_v2", {"operation_id": arguments["operation_id"]})["structuredContent"]
    assert receipt["tool"] == recovered["tool"] == "read_status_v2"
    assert receipt["operation_id"] == recovered["operation_id"] == arguments["operation_id"]
    with sqlite3.connect(ledger) as db:
        assert db.execute("SELECT count(*) FROM effects").fetchone()[0] == 1
        row = db.execute("SELECT phase,request_id,executions,result_hash FROM eval_tool_receipts").fetchone()
        assert row[:3] == ("mn_0123456789ab", arguments["request_id"], 16)
        saved = db.execute("SELECT result FROM results_v2").fetchone()[0]
        assert json.loads(saved) == recovered["result"]
        assert row[3] == receipt["result_sha256"] == recovered["result_sha256"] == sha256(saved.encode()).hexdigest()
