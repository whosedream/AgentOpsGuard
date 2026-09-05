from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import McpServer
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.gateway.app import app
from agentops_guard.gateway.transports.streamable_http import StreamableHttpTransport


@pytest.fixture
def standard_mcp_server(tmp_path: Path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server = tmp_path / "standard_mcp_server.py"
    server.write_text(
        f"""
from mcp.server import MCPServer
from mcp.types import Completion, PromptReference, ResourceTemplateReference

mcp = MCPServer("transport-test")

@mcp.tool()
def echo(text: str) -> str:
    \"\"\"Return the supplied text.\"\"\"
    return text

@mcp.resource("demo://status")
def status() -> str:
    \"\"\"Return server status.\"\"\"
    return "ready"

@mcp.resource("demo://records/{{record_id}}")
def record(record_id: str) -> str:
    \"\"\"Return one record.\"\"\"
    return f"record:{{record_id}}"

@mcp.prompt()
def greeting(name: str) -> str:
    \"\"\"Build a greeting prompt.\"\"\"
    return f"Hello, {{name}}"

@mcp.completion()
async def complete(ref, argument, context):
    if isinstance(ref, PromptReference):
        return Completion(values=["AgentOps"])
    if isinstance(ref, ResourceTemplateReference):
        return Completion(values=["record-1"])
    return Completion(values=[])

mcp.run(
    transport="streamable-http",
    host="127.0.0.1",
    port={port},
    stateless_http=True,
    json_response=True,
)
""",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, str(server)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(process.stderr.read())
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    else:
        process.terminate()
        raise AssertionError("standard MCP test server did not start")

    yield f"http://127.0.0.1:{port}/mcp"

    process.terminate()
    process.wait(timeout=5)


def test_streamable_http_transport_supports_standard_mcp_capabilities(
    standard_mcp_server: str,
):
    transport = StreamableHttpTransport(standard_mcp_server, timeout=5)

    tools = transport.list_tools()
    assert tools[0]["name"] == "echo"
    assert tools[0]["inputSchema"]["properties"]["text"]["type"] == "string"
    result = transport.call_tool("echo", {"text": "hello"})
    assert result["content"][0]["text"] == "hello"

    resources = transport.list_resources()
    assert resources[0]["uri"] == "demo://status"
    resource = transport.read_resource("demo://status")
    assert resource["contents"][0]["text"] == "ready"

    templates = transport.list_resource_templates()
    assert templates[0]["uriTemplate"] == "demo://records/{record_id}"
    templated_resource = transport.read_resource("demo://records/record-1")
    assert templated_resource["contents"][0]["text"] == "record:record-1"

    prompts = transport.list_prompts()
    assert prompts[0]["name"] == "greeting"
    prompt = transport.get_prompt("greeting", {"name": "AgentOps"})
    assert prompt["messages"][0]["content"]["text"] == "Hello, AgentOps"

    prompt_completion = transport.complete(
        "prompt",
        "greeting",
        {"name": "name", "value": "Agent"},
        {},
    )
    assert prompt_completion["completion"]["values"] == ["AgentOps"]
    resource_completion = transport.complete(
        "resource",
        "demo://records/{record_id}",
        {"name": "record_id", "value": "record"},
        {},
    )
    assert resource_completion["completion"]["values"] == ["record-1"]


def test_gateway_proxies_standard_mcp_without_bypassing_scanning(
    standard_mcp_server: str,
):
    project_id = "standard-mcp-integration"
    server_id = "standard-mcp-server"
    db = SessionLocal()
    try:
        ensure_project(db, project_id)
        db.merge(
            McpServer(
                id=server_id,
                project_id=project_id,
                name="standard test server",
                transport="streamable_http",
                url=standard_mcp_server,
                trust_level="internal",
                allowed_agents=[],
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    client = TestClient(app, headers={"X-AgentOps-Api-Key": "dev-agentops-key"})
    tools = client.get("/mcp/tools/list", params={"project_id": project_id})
    assert tools.status_code == 200
    assert tools.json()["tools"][0]["name"] == "echo"
    assert tools.json()["tools"][0]["serverId"] == server_id

    call = client.post(
        "/mcp/tools/call",
        params={"project_id": project_id},
        json={"serverId": server_id, "name": "echo", "arguments": {"text": "hello"}},
    )
    assert call.status_code == 200
    assert call.json()["content"][0]["text"] == "hello"
    assert call.json()["risk"]["risk_labels"] == []

    resources = client.get("/mcp/resources/list", params={"project_id": project_id})
    assert resources.status_code == 200
    assert resources.json()["resources"][0]["uri"] == "demo://status"
    resource = client.post(
        "/mcp/resources/read",
        params={"project_id": project_id},
        json={"serverId": server_id, "uri": "demo://status"},
    )
    assert resource.status_code == 200
    assert resource.json()["contents"][0]["text"] == "ready"
    assert resource.json()["risk"]["risk_labels"] == []

    templates = client.get(
        "/mcp/resources/templates/list",
        params={"project_id": project_id},
    )
    assert templates.status_code == 200
    assert templates.json()["resourceTemplates"][0]["uriTemplate"] == ("demo://records/{record_id}")
    templated_resource = client.post(
        "/mcp/resources/read",
        params={"project_id": project_id},
        json={"serverId": server_id, "uri": "demo://records/record-1"},
    )
    assert templated_resource.status_code == 200
    assert templated_resource.json()["contents"][0]["text"] == "record:record-1"

    unadvertised = client.post(
        "/mcp/resources/read",
        params={"project_id": project_id},
        json={"serverId": server_id, "uri": "demo://not-advertised"},
    )
    assert unadvertised.status_code == 404

    prompts = client.get("/mcp/prompts/list", params={"project_id": project_id})
    assert prompts.status_code == 200
    assert prompts.json()["prompts"][0]["name"] == "greeting"
    prompt = client.post(
        "/mcp/prompts/get",
        params={"project_id": project_id},
        json={"serverId": server_id, "name": "greeting", "arguments": {"name": "AgentOps"}},
    )
    assert prompt.status_code == 200
    assert prompt.json()["messages"][0]["content"]["text"] == "Hello, AgentOps"
    assert prompt.json()["risk"]["risk_labels"] == []

    completion = client.post(
        "/mcp/completion/complete",
        params={"project_id": project_id},
        json={
            "serverId": server_id,
            "refType": "prompt",
            "refValue": "greeting",
            "argument": {"name": "name", "value": "Agent"},
        },
    )
    assert completion.status_code == 200
    assert completion.json()["completion"] == {
        "values": ["AgentOps"],
        "total": 1,
        "hasMore": False,
    }
