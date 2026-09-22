from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from test_database_resilience import database, postgres_url as postgres_url
from test_gateway_streamable_http_transport import standard_mcp_server as standard_mcp_server

from agentops_guard.backend.database import Base, get_db
from agentops_guard.backend.database_resilience import database_http_boundary
from agentops_guard.backend.models import McpServer, McpTool
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.gateway import app as gateway


def test_real_mcp_success_followed_by_real_postgres_readonly_error_is_explicit(
    postgres_url, standard_mcp_server, monkeypatch,
):
    with database(postgres_url) as engine:
        # Schema bootstrap is not the request under test. Keep its DDL bounded
        # separately; the 250 ms request timeout resumes at this commit.
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL statement_timeout = '10s'"))
            Base.metadata.create_all(connection)
        with engine.connect() as connection:
            assert connection.scalar(text('SHOW statement_timeout')) == '250ms'
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        project_id, server_id = 'post_tool_' + uuid4().hex, 'server_' + uuid4().hex
        with sessions() as db:
            ensure_project(db, project_id)
            db.add(McpServer(id=server_id, project_id=project_id, name='controlled MCP',
                transport='streamable_http', url=standard_mcp_server, trust_level='internal',
                allowed_agents=[], status='active'))
            db.add(McpTool(id=server_id+':echo', project_id=project_id, server_id=server_id,
                name='echo', description='Echo text', status='active',
                input_schema={'type': 'object', 'properties': {'text': {'type': 'string'}}, 'required': ['text']},
                annotations={'readOnlyHint': True}))
            db.commit()

        def scoped_db():
            with database_http_boundary(), sessions() as db:
                yield db

        calls = []
        actual_call, actual_scan = gateway._call_upstream_tool, gateway.scan_content

        def record_call(*args):
            result = actual_call(*args)  # Actual SDK client and real MCP server.
            calls.append(result)
            return result

        def readonly_after_tool(request, db):
            if request.source == 'mcp_tool_result':
                # Transaction-local fault, not a global database setting. The
                # next real content INSERT fails with PostgreSQL SQLSTATE 25006.
                db.execute(text('SET LOCAL transaction_read_only = on'))
            return actual_scan(request, db)

        monkeypatch.setitem(gateway.app.dependency_overrides, get_db, scoped_db)
        monkeypatch.setattr(gateway, '_call_upstream_tool', record_call)
        monkeypatch.setattr(gateway, 'scan_content', readonly_after_tool)
        client = TestClient(gateway.app, headers={'X-AgentOps-Api-Key': 'dev-agentops-key'})
        response = client.post('/mcp/tools/call', params={'project_id': project_id}, json={
            'serverId': server_id, 'name': 'echo', 'arguments': {'text': 'private-unreleased-result'}})
        assert response.status_code == 503
        assert response.json()['detail'] == {'code': 'post_tool_database_unavailable', 'tool_execution': {
            'state': 'response_received', 'tool_reported_error': False,
            'result_released': False, 'automatic_retry_allowed': False}}
        assert len(calls) == 1 and calls[0].get('isError') is False
        assert 'private-unreleased-result' not in response.text
        assert 'Retry-After' not in response.headers
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT current_setting('transaction_read_only')")) == 'off'
