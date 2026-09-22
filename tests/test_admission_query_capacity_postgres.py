"""A reserved pool protects fresh status reads without a cached authorization."""
from contextlib import ExitStack
import importlib.util
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

from test_api_key_activity_postgres import private_activity_pg as private_activity_pg
from test_admission_health import seed_health_store
from agentops_guard.admission.app import create_app
from agentops_guard.admission.store import AdmissionSettings, Grant, Store, now


def test_full_deposit_pool_does_not_starve_fresh_status_authentication(private_activity_pg):
    reference, _, _ = private_activity_pg
    settings = AdmissionSettings(enabled=True, database_url=reference.url.render_as_string(),
                                 encryption_key=Fernet.generate_key().decode(), request_timeout_seconds=1)
    store = Store(settings, isolate_queries=True)
    try:
        store.initialize()
        token, grant_id, payload = seed_health_store(store)
        assert store.engine.pool.size() == 12 and store.query_engine.pool.size() == 3
        assert store.engine.pool._max_overflow == store.query_engine.pool._max_overflow == 0
        with TestClient(create_app(settings, store=store)) as client:
            client.headers["X-AgentOps-Admission-Key"] = token
            assert client.post("/v1/admissions", json=payload).status_code == 202
            with ExitStack() as holds:
                for _ in range(12):
                    holds.enter_context(store.engine.connect())
                assert store.engine.pool.checkedout() == 12
                assert client.get("/readyz").status_code == 200
                response = client.get("/v1/admissions/" + payload["requestId"])
                assert response.status_code == 200 and response.json()["acceptanceEvidence"] == "record_observed"
                assert not response.json()["durabilityConfirmed"]
                # Even while deposits exhaust their pool, committed revocation
                # must immediately affect the next status read, with no cache.
                with store.sessions(bind=store.query_engine) as db:
                    db.get(Grant, grant_id).revoked_at = now()
                    db.commit()
                assert client.get("/v1/admissions/" + payload["requestId"]).status_code == 401
                assert store.engine.pool.checkedout() == 12
    finally:
        store.dispose()


def test_admission_probe_measures_its_own_database_and_real_write(private_activity_pg, monkeypatch):
    reference, _, _ = private_activity_pg
    settings = AdmissionSettings(enabled=True, database_url=reference.url.render_as_string(),
                                 encryption_key=Fernet.generate_key().decode())
    spec = importlib.util.spec_from_file_location("controlled_admission_probe_runtime",
        Path(__file__).resolve().parents[1] / "evals/multinode-runtime/runtime.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    import agentops_guard.admission.store as store_module
    monkeypatch.setattr(store_module, "AdmissionSettings", lambda: settings)
    with reference.begin() as db:
        db.execute(text("CREATE TABLE IF NOT EXISTS eval_database_probe (id integer PRIMARY KEY, value integer NOT NULL)"))
        db.execute(text("INSERT INTO eval_database_probe VALUES (1,0) ON CONFLICT(id) DO NOTHING"))
    healthy = runtime.admission_database_probe({})
    assert healthy["database_target"] == "admission" and healthy["role_writable"] and healthy["commit_confirmed"]
    with reference.begin() as held:
        held.execute(text("LOCK TABLE eval_database_probe IN ACCESS EXCLUSIVE MODE"))
        blocked = runtime.admission_database_probe({})
        assert blocked["role_writable"] and not blocked["commit_confirmed"]
        assert blocked["error"] == "55P03"
    assert runtime.admission_database_probe({})["commit_confirmed"]
