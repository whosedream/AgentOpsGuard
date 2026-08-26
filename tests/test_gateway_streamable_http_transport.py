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
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("transport-test", host="127.0.0.1", port={port})

@mcp.tool()
def echo(text: str) -> str:
    \"\"\"Return the supplied text.\"\"\"
    return text

@mcp.resource("demo://status")
def status() -> str:
    \"\"\"Return server status.\"\"\"
    return "ready"

@mcp.prompt()
def greeting(name: str) -> str:
    \"\"\"Build a greeting prompt.\"\"\"
    return f"Hello, {{name}}"

mcp.run("streamable-http")
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

    prompts = transport.list_prompts()
    assert prompts[0]["name"] == "greeting"
    prompt = transport.get_prompt("greeting", {"name": "AgentOps"})
    assert prompt["messages"][0]["content"]["text"] == "Hello, AgentOps"


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

    client = TestClient(app)
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
