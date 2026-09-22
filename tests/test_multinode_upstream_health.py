import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import anyio
from fastapi import HTTPException
import pytest
from test_database_resilience import postgres_url as postgres_url, database


SPEC = importlib.util.spec_from_file_location("eval_upstream_health",
    Path(__file__).resolve().parents[1] / "evals/multinode-runtime/runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def test_upstream_readiness_checks_its_own_database_connection(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "check_database_ready", lambda engine: calls.append(engine))
    assert anyio.run(runtime.upstream_ready, None).status_code == 200
    assert calls == [runtime.engine]


def test_upstream_readiness_rejects_unavailable_database_without_details(monkeypatch):
    def unavailable(engine):
        raise HTTPException(503, "private connection details")
    monkeypatch.setattr(runtime, "check_database_ready", unavailable)
    response = anyio.run(runtime.upstream_ready, None)
    assert response.status_code == 503
    assert response.body == b""


def test_upstream_readiness_does_not_mask_programming_errors(monkeypatch):
    def broken(engine):
        raise ValueError("bug")
    monkeypatch.setattr(runtime, "check_database_ready", broken)
    with pytest.raises(ValueError, match="bug"):
        anyio.run(runtime.upstream_ready, None)


def test_cluster_and_proxy_both_use_dependency_readiness():
    source = (Path(__file__).resolve().parents[1] / "scripts/verify_multinode_capacity.py").read_text()
    assert '"httpGet": {"path": "/readyz", "port": 8091}' in source
    assert '"port": 8091, "healthPath": "/readyz"' in source


@pytest.mark.parametrize('code,expected', [('57014', '57014'), ('25006', '25006'),
    (None, 'unclassified'), ('private-value', 'unclassified'), (['private-value'], 'unclassified')])
def test_database_diagnostics_keep_only_request_id_and_fixed_codes(capsys, code, expected):
    token = runtime.request_context.set('mn_0123456789ab:121')
    try:
        assert runtime.database_error_event(SimpleNamespace(
            original_exception=SimpleNamespace(sqlstate=code, message='private-value'),
            is_disconnect=True, statement='private-query', parameters={'secret': 'private-value'})) is None
        output = capsys.readouterr().out
        assert 'private-' not in output
        row = json.loads(output.removeprefix('EVAL_EVENT '))
        assert row['stage'] == 'database_error' and row['code'] == expected
        assert row['disconnect'] is True and row['id'] == 'mn_0123456789ab:121'
    finally:
        runtime.request_context.reset(token)


def test_database_diagnostics_ignore_non_test_request_identifiers(capsys):
    token = runtime.request_context.set('private-request')
    try:
        runtime.database_error_event(SimpleNamespace(original_exception=ValueError('private'), is_disconnect=False))
        assert capsys.readouterr().out == ''
    finally:
        runtime.request_context.reset(token)


def test_queue_seed_persists_tools_before_reviewing_revisions(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from agentops_guard.backend.database import Base
    from agentops_guard.backend.models import McpTool, ToolExecutionPolicy
    from agentops_guard.backend.services import scanner_rule_packs

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(runtime, "SessionLocal", sessions)
    monkeypatch.setattr(runtime, "tables", lambda: None)
    monkeypatch.setattr(scanner_rule_packs, "install_scanner_rule_pack", lambda *a, **kw: None)
    try:
        seeded = runtime.seed({"phase": "mn_queue_seed_regression", "queue_policy": True})
        with sessions() as db:
            policies = db.query(ToolExecutionPolicy).all()
            assert len(policies) == 2
            for policy in policies:
                tool = db.get(McpTool, policy.tool_id)
                assert tool.server_id == seeded["server_id"]
                assert tool.current_revision_id
                assert policy.queue_enabled and policy.retry_mode == "never"
                assert len(policy.evidence_sha256) == 64
    finally:
        engine.dispose()


def test_independent_receipt_fixture_is_registered_with_a_reviewed_query_contract(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from agentops_guard.backend.database import Base
    from agentops_guard.backend.models import ToolExecutionPolicy
    from agentops_guard.backend.services.tool_receipts import ReceiptContract, validate_contract

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(runtime, "SessionLocal", sessions)
    monkeypatch.setattr(runtime, "RECEIPT_FIXTURE_PATH", Path(__file__).parent / "fixtures/receipt_mcp_server.py")
    try:
        seed = runtime.seed_receipts({"phase": "mn_receipt_contract"})
        with sessions() as db:
            policy = db.query(ToolExecutionPolicy).one()
            contract = ReceiptContract.model_validate(policy.receipt_contract)
            tool, lookup = validate_contract(db, "mn_receipt_contract", policy.tool_id, contract)
            assert tool.server_id == seed["server_id"]
            assert lookup.name == "lookup_receipt" and tool.name == "echo"
            assert policy.retry_mode == "never" and policy.queue_enabled
            assert len(policy.evidence_sha256) == 64
    finally:
        engine.dispose()


def test_stage_measurement_preserves_failure_and_does_not_record_arguments():
    token = runtime.stage_context.set({})
    try:
        def fail(secret):
            raise ValueError(secret)
        with pytest.raises(ValueError, match="private-value"):
            runtime.measured(fail, "policy")("private-value")
        measurements = runtime.stage_context.get()
        assert measurements["policy"]["calls"] == 1
        assert measurements["policy"]["errors"] == 1
        assert measurements["policy"]["ms"] >= 0
        assert "private" not in json.dumps(measurements)
    finally:
        runtime.stage_context.reset(token)


def test_real_database_probe_distinguishes_role_from_committable_write(postgres_url, monkeypatch):
    from sqlalchemy import text

    with database(postgres_url) as engine, database(postgres_url) as peer:
        monkeypatch.setattr(runtime, "engine", engine)
        runtime.tables()
        healthy = runtime.database_probe({})
        assert healthy["role_writable"] and healthy["commit_confirmed"]
        with peer.begin() as held:
            held.execute(text("LOCK TABLE eval_database_probe IN ACCESS EXCLUSIVE MODE"))
            blocked = runtime.database_probe({})
        assert blocked["role_writable"] and not blocked["commit_confirmed"]
        assert blocked["error"] == "55P03" and blocked["total_ms"] < 2000
        assert runtime.database_probe({})["commit_confirmed"]
