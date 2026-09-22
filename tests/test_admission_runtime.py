"""Two real PG instances and a real MCP server; not a physical multi-host SLA test."""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
from uuid import uuid4

from cryptography.fernet import Fernet
import httpx
import psycopg
import pytest
from pydantic import SecretStr
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
import uvicorn

from test_tool_receipts_runtime import durable_downstream as durable_downstream
from agentops_guard.admission.app import create_app
from agentops_guard.admission.importer import handoff, provision
from agentops_guard.admission.store import AdmissionSettings, Entry, Store, now
from agentops_guard.backend.config import Settings, get_settings
from agentops_guard.backend.database import Base
from agentops_guard.backend.database_diagnostics import postgres_wait_snapshot
from agentops_guard.backend.database_resilience import create_database_engine
from agentops_guard.backend.models import ApiKey, McpServer, McpTool, ToolExecutionPolicy, ToolInvocation
from agentops_guard.backend.services import tool_invocations as inv, jobs
from agentops_guard.backend.services.projects import ensure_project


@contextmanager
def disposable_postgres():
    image = os.environ.get("AGENTOPS_TEST_POSTGRES_IMAGE")
    if not image:
        pytest.skip("Set AGENTOPS_TEST_POSTGRES_IMAGE for real admission tests")
    name, password = "agentops-admission-test-" + secrets.token_hex(6), secrets.token_hex(24)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    # Docker can allocate a different random published port after a stop/start.
    # Pin this test-only listener so the fault is a DB outage, not a changed DSN.
    result = subprocess.run(["docker", "run", "-d", "--name", name, "--publish", f"127.0.0.1:{port}:5432",
        "--env-file", "/dev/stdin", image], input="POSTGRES_PASSWORD=" + password + "\n",
        capture_output=True, text=True)
    assert result.returncode == 0, "Disposable PG startup failed"
    try:
        url = make_url(f"postgresql+psycopg://postgres:{password}@127.0.0.1:{port}/postgres")

        def ready():
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    with psycopg.connect(host="127.0.0.1", port=int(port), user="postgres",
                                         password=password, connect_timeout=2):
                        return
                except psycopg.OperationalError:
                    time.sleep(.2)
            pytest.fail("Disposable PG not ready", pytrace=False)

        ready()
        yield url, name, ready
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True, check=True)


def seed(sessions, url):
    project, server, key_id = "adm_rt_" + uuid4().hex, "srv_" + uuid4().hex, "key_" + uuid4().hex
    with sessions() as db:
        ensure_project(db, project)
        db.add(ApiKey(id=key_id, project_id=project, name="controlled runtime", scopes=["mcp:invoke"],
                      key_hash=sha256(secrets.token_bytes(32)).hexdigest()))
        db.add(McpServer(id=server, project_id=project, name="receipt runtime", transport="streamable_http",
            url=url, trust_level="internal", allowed_agents=[], status="active"))
        db.flush()
        revisions = {}
        for name in ("echo_v2", "lookup_receipt_v2", "lookup_result_v2"):
            schema = {"type": "object", "properties": {"operation_id": {"type": "string"}}, "required": ["operation_id"]}
            if name == "echo_v2":
                schema["properties"]["text"] = {"type": "string"}
                schema["required"].append("text")
            db.add(McpTool(id=server + ":" + name, name=name, project_id=project, server_id=server,
                description="Controlled durable echo", status="active", input_schema=schema, annotations={}))
            db.flush()
            revisions[name] = inv.current_revision(db, project, server + ":" + name).content_digest
        db.add(ToolExecutionPolicy(tool_id=server + ":echo_v2", project_id=project,
            revision_digest=revisions["echo_v2"], queue_enabled=True, retry_mode="never",
            evidence_sha256="a" * 64, updated_by="runtime-test", receipt_contract={
                "protocol": "agentops-receipt-v2", "key_argument": "operation_id",
                "lookup_tool_id": server + ":lookup_receipt_v2", "lookup_revision_digest": revisions["lookup_receipt_v2"],
                "result_tool_id": server + ":lookup_result_v2", "result_revision_digest": revisions["lookup_result_v2"],
                "retention_seconds": 3600}))
        db.commit()
    return project, server, key_id


@pytest.mark.skipif(os.environ.get("AGENTOPS_TEST_ADMISSION_RUNTIME") != "1",
                    reason="Opt-in 3 x 180 two-PG fault benchmark")
def test_two_databases_business_outage_three_rounds(durable_downstream, monkeypatch, tmp_path):
    import sqlite3
    from concurrent.futures import ThreadPoolExecutor

    upstream_url, effect_ledger, *_ = durable_downstream
    monkeypatch.setattr(get_settings(), "invocation_encryption_key", SecretStr(Fernet.generate_key().decode()))
    monkeypatch.setattr(get_settings(), "semantic_scanner_mode", "disabled")
    report = {"scope": "single WSL host, two PostgreSQL containers, HTTP admission, real MCP",
              "production_ha_verified": False, "independent_clock_verified": False,
              "semantic_model_enabled": False, "rounds": [], "passed": False}
    root = Path(__file__).resolve().parents[1]
    frozen = sorted([*root.joinpath("src").rglob("*.py"), *root.joinpath("alembic/versions").glob("*.py"),
                     Path(__file__).resolve(), root / "tests/fixtures/receipt_mcp_server.py",
                     root / "pyproject.toml", root / "uv.lock"])
    report["source_sha256"] = {str(p.relative_to(root)): sha256(p.read_bytes()).hexdigest() for p in frozen}
    with disposable_postgres() as (business_url, business_container, ready), disposable_postgres() as (admission_url, admission_container, _):
        business = create_database_engine(Settings(database_url=business_url.render_as_string(hide_password=False),
                                                   database_statement_timeout_ms=10000))
        Base.metadata.create_all(business)
        sessions = sessionmaker(bind=business, expire_on_commit=False)
        monkeypatch.setattr(jobs, "SessionLocal", sessions)
        project, server, key_id = seed(sessions, upstream_url)
        settings = AdmissionSettings(enabled=True, database_url=admission_url.render_as_string(hide_password=False),
                                      encryption_key=Fernet.generate_key().decode(), lease_seconds=5)
        store = Store(settings)
        store.initialize()
        with sessions() as db:
            _, token = provision(store, db, key_id=key_id, tool_ids=[server + ":echo_v2"])
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        port = sock.getsockname()[1]
        http_server = uvicorn.Server(uvicorn.Config(create_app(settings, store=store), access_log=False, log_level="critical"))
        thread = threading.Thread(target=lambda: http_server.run(sockets=[sock]), daemon=True)
        thread.start()
        while not http_server.started:
            assert thread.is_alive()
            time.sleep(.01)
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=5, trust_env=False,
                              headers={"X-AgentOps-Admission-Key": token}) as client:
                for run in range(3):
                    requests, observations = [], []
                    subprocess.run(["docker", "stop", "-t", "1", business_container], capture_output=True, check=True)
                    outage = time.monotonic()
                    for i in range(180):
                        wait = outage + i / 6 - time.monotonic()
                        if wait > 0:
                            time.sleep(wait)
                        payload = {"requestId": str(uuid4()), "serverId": server, "name": "echo_v2",
                                   "arguments": {"text": f"round {run} item {i}"}}
                        started = time.monotonic()
                        response = client.post("/v1/admissions", json=payload)
                        elapsed = (time.monotonic() - started) * 1000
                        queried = client.get("/v1/admissions/" + payload["requestId"])
                        observations.append({"index": i, "accepted_http": response.status_code,
                            "query_http": queried.status_code, "accept_ms": round(elapsed, 3)})
                        assert response.status_code == 202 and queried.status_code == 200
                        requests.append(payload)
                        if i == 0:
                            assert handoff(store, sessions, store.claim())
                    # Same identifier is delivered ten extra times under the fault.
                    with ThreadPoolExecutor(max_workers=10) as duplicates:
                        statuses = list(duplicates.map(lambda _: client.post("/v1/admissions", json=requests[0]).status_code, range(10)))
                    assert statuses == [202] * 10
                    remaining = outage + 30 - time.monotonic()
                    if remaining > 0:
                        time.sleep(remaining)
                    subprocess.run(["docker", "start", business_container], capture_output=True, check=True)
                    ready()
                    restored = time.monotonic()
                    with store.sessions() as db:
                        db.query(Entry).filter_by(state="accepted").update({"next_check_at": now()})
                        db.commit()
                    for _ in range(180):
                        claim = store.claim()
                        assert claim is not None
                        assert handoff(store, sessions, claim)
                    with sessions() as db:
                        rows = db.query(ToolInvocation).filter(ToolInvocation.request_id.in_([p["requestId"] for p in requests])).all()
                        assert len(rows) == 180
                        job_ids = [row.job_id for row in rows]
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        outcomes = list(pool.map(jobs.execute_job, job_ids))
                    assert all(r["state"] == "succeeded" for r in outcomes)
                    with store.sessions() as db:
                        db.query(Entry).filter_by(state="imported").update({"next_check_at": now()})
                        db.commit()
                    for _ in range(180):
                        assert handoff(store, sessions, store.claim())
                    for payload in requests:
                        status = client.get("/v1/admissions/" + payload["requestId"]).json()
                        assert status["state"] == "completed" and status["businessState"] == "succeeded"
                    with sqlite3.connect(effect_ledger) as ledger:
                        effects = ledger.execute("SELECT count(*) FROM effects").fetchone()[0]
                    assert effects == 180 * (run + 1)
                    with business.connect() as connection:
                        diagnostics = postgres_wait_snapshot(connection)
                    report["rounds"].append({"submitted": 180, "accepted": 180, "queryable": 180,
                        "extra_duplicate_submissions": 10, "business_success": 180,
                        "total_unique_effects": effects, "additional_duplicate_effects": 0,
                        "accept_p95_ms": sorted(o["accept_ms"] for o in observations)[170],
                        "recovery_to_all_observed_seconds": round(time.monotonic() - restored, 3),
                        "requests": observations, "database_snapshot_after_recovery": diagnostics})
                # The new admission store has its own failure boundary: do not claim 202 if it is down.
                subprocess.run(["docker", "stop", "-t", "1", admission_container], capture_output=True, check=True)
                failed = client.post("/v1/admissions", json={**requests[0], "requestId": str(uuid4())})
                assert failed.status_code == 503
                assert client.get("/v1/admissions/" + requests[0]["requestId"]).status_code == 503
                report["admission_store_unavailable_rejected"] = True
                report["passed"] = True
        finally:
            http_server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()
            sock.close()
            store.engine.dispose()
            business.dispose()
            target = Path(os.environ.get("AGENTOPS_ADMISSION_REPORT", str(tmp_path / "admission-report.json")))
            report["frozen_inputs_unchanged"] = all(sha256((root / p).read_bytes()).hexdigest() == h
                                                   for p, h in report["source_sha256"].items())
            report["passed"] = report["passed"] and report["frozen_inputs_unchanged"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    assert report["passed"]
