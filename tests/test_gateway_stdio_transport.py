import sys
from pathlib import Path

from agentops_guard.gateway.transports.stdio import StdioProcessManager, StdioTransport


def test_stdio_transport_lists_and_calls_tools(tmp_path: Path):
    server = tmp_path / "fake_mcp.py"
    server.write_text(
        """
import json
import sys

header = b""
while b"\\r\\n\\r\\n" not in header:
    header += sys.stdin.buffer.read(1)
length = 0
for line in header.decode("ascii").split("\\r\\n"):
    if line.lower().startswith("content-length:"):
        length = int(line.split(":", 1)[1].strip())
request = json.loads(sys.stdin.buffer.read(length).decode("utf-8"))
if request["method"] == "tools/list":
    result = {"tools": [{"name": "fake.echo", "description": "Echo", "inputSchema": {"type": "object"}}]}
elif request["method"] == "tools/call":
    result = {"content": [{"type": "text", "text": request["params"]["arguments"].get("text", "")}]}
else:
    result = {}
payload = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode("utf-8")
sys.stdout.buffer.write(b"Content-Length: " + str(len(payload)).encode("ascii") + b"\\r\\n\\r\\n" + payload)
""".strip(),
        encoding="utf-8",
    )
    transport = StdioTransport(sys.executable, [str(server)])
    assert transport.list_tools()[0]["name"] == "fake.echo"
    assert transport.call_tool("fake.echo", {"text": "hello"})["content"][0]["text"] == "hello"


def test_stdio_process_manager_reuses_process_and_restarts(tmp_path: Path):
    server = tmp_path / "loop_mcp.py"
    server.write_text(
        """
import json
import sys

while True:
    header = b""
    while b"\\r\\n\\r\\n" not in header:
        chunk = sys.stdin.buffer.read(1)
        if not chunk:
            sys.exit(0)
        header += chunk
    length = 0
    for line in header.decode("ascii").split("\\r\\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    request = json.loads(sys.stdin.buffer.read(length).decode("utf-8"))
    if request["method"] == "tools/list":
        result = {"tools": [{"name": "loop.echo", "description": "Echo", "inputSchema": {}}]}
    else:
        result = {"content": [{"type": "text", "text": request["params"]["arguments"].get("text", "")}]}
    payload = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode("utf-8")
    sys.stdout.buffer.write(b"Content-Length: " + str(len(payload)).encode("ascii") + b"\\r\\n\\r\\n" + payload)
    sys.stdout.buffer.flush()
""".strip(),
        encoding="utf-8",
    )
    manager = StdioProcessManager(sys.executable, [str(server)], timeout=3)
    try:
        assert manager.request("tools/list", {})["result"]["tools"][0]["name"] == "loop.echo"
        first_pid = manager._process.pid
        assert manager.request("tools/call", {"name": "loop.echo", "arguments": {"text": "hi"}})["result"]["content"][0]["text"] == "hi"
        assert manager._process.pid == first_pid
        manager.restart()
        assert manager._process.pid != first_pid
    finally:
        manager.close()


def test_stdio_transport_returns_structured_error_on_invalid_output(tmp_path: Path):
    server = tmp_path / "bad_mcp.py"
    server.write_text("import sys; sys.stdout.write('not json')", encoding="utf-8")
    result = StdioTransport(sys.executable, [str(server)]).call_tool("bad", {})
    assert result["isError"] is True
