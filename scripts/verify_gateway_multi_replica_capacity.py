from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from uuid import uuid4

import httpx

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.models import McpServer, McpTool
from agentops_guard.backend.services.api_keys import create_api_key
from agentops_guard.backend.services.projects import ensure_project


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_for_port(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            error = process.stderr.read(4_096) if process.stderr else "process exited"
            raise RuntimeError(error)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"process did not listen on port {port}")


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _call_gateway(port: int, token: str, server_id: str) -> httpx.Response:
    with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
        return client.post(
            f"http://127.0.0.1:{port}/mcp/tools/call",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "serverId": server_id,
                "name": "slow_echo",
                "arguments": {"text": "capacity-check"},
            },
        )


def _wait_for_marker(marker: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if marker.exists():
            return
        time.sleep(0.02)
    raise RuntimeError("upstream call did not start")


def main() -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("This verification requires PostgreSQL")
    if not os.environ.get("AGENTOPS_REDIS_URL"):
        raise RuntimeError("This verification requires Redis")

    suffix = uuid4().hex
    project_id = f"multi_gateway_project_{suffix}"
    server_id = f"multi_gateway_server_{suffix}"
    upstream_port = _free_port()
    gateway_ports = [_free_port(), _free_port()]

    with tempfile.TemporaryDirectory(prefix="agentops-multi-gateway-") as temp_dir:
        marker = Path(temp_dir) / "upstream-calls"
        upstream_script = Path(temp_dir) / "slow_upstream.py"
        upstream_script.write_text(
            f'''
from mcp.server import MCPServer
from pathlib import Path
import time

server = MCPServer("capacity-upstream")

@server.tool()
def slow_echo(text: str) -> str:
    with Path({str(marker)!r}).open("a", encoding="utf-8") as file:
        file.write("x")
    time.sleep(1)
    return text

server.run(
    transport="streamable-http",
    host="127.0.0.1",
    port={upstream_port},
    stateless_http=True,
    json_response=True,
)
'''.strip(),
            encoding="utf-8",
        )
        upstream = subprocess.Popen(
            [sys.executable, str(upstream_script)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        gateways: list[subprocess.Popen[str]] = []
        try:
            _wait_for_port(upstream, upstream_port)
            db = SessionLocal()
            try:
                ensure_project(db, project_id)
                db.add(
                    McpServer(
                        id=server_id,
                        project_id=project_id,
                        name="multi gateway upstream",
                        transport="streamable_http",
                        url=f"http://127.0.0.1:{upstream_port}/mcp",
                        trust_level="internal",
                        allowed_agents=[],
                        status="active",
                    )
                )
                db.add(
                    McpTool(
                        id=f"{server_id}:slow_echo",
                        project_id=project_id,
                        server_id=server_id,
                        name="slow_echo",
                        description="Return text after a short delay.",
                        input_schema={
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                        },
                        annotations={"readOnlyHint": True},
                        status="active",
                    )
                )
                _, token = create_api_key(
                    db,
                    project_id,
                    "multi-gateway-verification",
                    ["mcp:read", "mcp:invoke"],
                    agent_id="capacity-agent",
                )
                db.commit()
            finally:
                db.close()

            for port in gateway_ports:
                environment = os.environ.copy()
                environment.update(
                    {
                        "AGENTOPS_ENV": "test",
                        "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "false",
                        "AGENTOPS_API_KEY": "unused-test-bootstrap",
                        "AGENTOPS_OPERATOR_API_KEY": "unused-test-operator",
                        "AGENTOPS_GATEWAY_CONCURRENCY_BACKEND": "redis",
                        "AGENTOPS_GATEWAY_MAX_CONCURRENCY_PER_SERVER": "1",
                        "AGENTOPS_GATEWAY_CAPACITY_WAIT_SECONDS": "0.05",
                        "AGENTOPS_GATEWAY_CONCURRENCY_LEASE_SECONDS": "60",
                        "AGENTOPS_MCP_PUBLIC_URL": f"http://127.0.0.1:{port}/mcp",
                        "AGENTOPS_MCP_ALLOWED_HOSTS": "127.0.0.1,127.0.0.1:*",
                        "AGENTOPS_MCP_ALLOWED_ORIGINS": "http://127.0.0.1:3000",
                        "AGENTOPS_SEMANTIC_SCANNER_MODE": "disabled",
                        "AGENTOPS_OPA_URL": "",
                    }
                )
                gateway = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "agentops_guard.gateway.app:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                    ],
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                gateways.append(gateway)
                _wait_for_port(gateway, port)

            with ThreadPoolExecutor(max_workers=2) as pool:
                first_future = pool.submit(
                    _call_gateway,
                    gateway_ports[0],
                    token,
                    server_id,
                )
                _wait_for_marker(marker)
                rejected = _call_gateway(gateway_ports[1], token, server_id)
                first = first_future.result(timeout=10)

            if first.status_code != 200 or first.json().get("isError"):
                raise RuntimeError("first Gateway call did not complete")
            if rejected.status_code != 429:
                raise RuntimeError("second Gateway replica exceeded the shared capacity limit")

            after_release = _call_gateway(gateway_ports[1], token, server_id)
            if after_release.status_code != 200 or after_release.json().get("isError"):
                raise RuntimeError("capacity did not recover after the first call")
            if marker.read_text(encoding="utf-8") != "xx":
                raise RuntimeError("unexpected number of upstream calls")

            result: dict[str, Any] = {
                "real_gateway_processes": 2,
                "real_mcp_upstream": True,
                "shared_redis_capacity": True,
                "second_replica_status": rejected.status_code,
                "capacity_recovered": True,
                "upstream_calls": 2,
            }
            v1_python = os.environ.get("AGENTOPS_MCP_V1_PYTHON")
            if v1_python:
                v1_environment = os.environ.copy()
                v1_environment.update(
                    {
                        "AGENTOPS_TEST_MCP_URL": (
                            f"http://127.0.0.1:{gateway_ports[0]}/mcp"
                        ),
                        "AGENTOPS_TEST_MCP_TOKEN": token,
                    }
                )
                v1_check = subprocess.run(
                    [v1_python, "scripts/verify_mcp_v1_client.py"],
                    env=v1_environment,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if v1_check.returncode != 0:
                    raise RuntimeError("MCP 1.x client verification failed")
                result["mcp_v1_client"] = json.loads(v1_check.stdout)
                if marker.read_text(encoding="utf-8") != "xxx":
                    raise RuntimeError("MCP 1.x client did not reach the upstream exactly once")
                result["upstream_calls"] = 3
        finally:
            for gateway in gateways:
                _stop_process(gateway)
            _stop_process(upstream)

    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
