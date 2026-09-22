from contextlib import asynccontextmanager
import importlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import anyio
import httpx2
import pytest

from agentops_guard.backend.models import McpServer
from agentops_guard.gateway.concurrency import server_call_slot
from agentops_guard.gateway.transports.errors import UpstreamTransportError
from agentops_guard.gateway.transports.legacy_http import LegacyHttpTransport
from agentops_guard.gateway.transports.streamable_http import StreamableHttpTransport


def test_legacy_drip_response_cannot_extend_total_deadline_or_retry():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            calls.append(1)
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                try:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
                time.sleep(0.05)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        with pytest.raises(UpstreamTransportError, match="timeout"):
            with server_call_slot("legacy-deadline", limit=1, wait_seconds=0):
                LegacyHttpTransport(f"http://127.0.0.1:{server.server_port}", timeout=1).call_tool("probe", {})
        assert time.monotonic() - started < 2
        with server_call_slot("legacy-deadline", limit=1, wait_seconds=0):
            pass
        assert len(calls) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_deadline_includes_initialization_and_finishes_cleanup_before_release(monkeypatch):
    cleaned = []

    @asynccontextmanager
    async def initializing(self):
        try:
            await anyio.sleep(5)
            yield None
        finally:
            cleaned.append(True)

    monkeypatch.setattr(StreamableHttpTransport, "_session", initializing)
    with pytest.raises(UpstreamTransportError, match="timeout"):
        StreamableHttpTransport("http://controlled.invalid", timeout=0.05).call_tool("probe", {})
    assert cleaned == [True]


@pytest.mark.parametrize("timeout", [False, True])
def test_real_httpx2_task_group_error_is_normalized_without_error_text(monkeypatch, timeout):
    async def failed(*_args):
        errors = [httpx2.ConnectError("private value")]
        if timeout:
            errors.append(TimeoutError("private timeout context"))
        raise ExceptionGroup("transport details must not escape", errors)

    monkeypatch.setattr(StreamableHttpTransport, "_call_tool", failed)
    with pytest.raises(UpstreamTransportError, match="^timeout$" if timeout else "^http_error$"):
        StreamableHttpTransport("http://controlled.invalid").call_tool("probe", {})


@pytest.mark.parametrize("transport", ["streamable_http", "legacy_http"])
def test_gateway_preserves_configured_budget_and_unknown_outcome(transport, monkeypatch):
    module = importlib.import_module("agentops_guard.gateway.app")
    settings = module.get_settings().model_copy(update={"gateway_call_timeout_seconds": 0.125})
    monkeypatch.setattr(module, "get_settings", lambda: settings)
    calls = []

    def fail(self, *_args):
        calls.append(self.timeout)
        raise UpstreamTransportError("timeout")

    cls = StreamableHttpTransport if transport == "streamable_http" else LegacyHttpTransport
    monkeypatch.setattr(cls, "call_tool", fail)
    result = module._call_upstream_tool(McpServer(transport=transport, url="http://controlled.invalid"), "probe", {})
    assert calls == [0.125]
    assert result["isError"] is True
    assert result["upstreamError"] == {"code": "timeout"}
