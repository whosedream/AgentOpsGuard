"""Scoring-only retries, fixed failure categories and an overall time budget."""
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import get_args

import anyio
import httpx
import pytest

from test_tool_invocations import setup_invocation as setup_invocation
from test_gateway import client
from agentops_guard.backend.schemas import ScanRequest, SemanticFailureReason
from agentops_guard.backend.services import scanner, semantic_scanner as semantic


def test_every_service_failure_category_fits_persisted_assessment_contract():
    assert semantic.SEMANTIC_FAILURE_REASONS <= set(get_args(SemanticFailureReason))


def remote(monkeypatch, handler, timeout=1):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(semantic.httpx, "AsyncClient", lambda **kwargs:
        real_client(**kwargs, transport=httpx.MockTransport(handler)))
    return semantic.RemoteSemanticScanner("http://controlled.invalid", "shadow", .9, timeout)


def test_retry_keeps_same_bounded_redacted_input_and_records_first_failure(monkeypatch, caplog):
    calls = []
    failures = semantic.SEMANTIC_SCORING_FAILURES_COUNTER.labels(reason="connection_failed")
    recovered = semantic.SEMANTIC_SCORING_REQUESTS_COUNTER.labels(outcome="recovered")
    before_failures, before_recovered = failures._value.get(), recovered._value.get()

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("private transport details", request=request)
        return httpx.Response(200, json={"score": .1, "model": semantic.SEMANTIC_MODEL_ID})

    service = remote(monkeypatch, handler)
    with caplog.at_level(logging.INFO):
        result = service.assess(ScanRequest(content="password=private-fixture " + "normal " * 1000))
    assert result.status == "ok" and result.attempts == 2
    assert result.attempt_errors == ["connection_failed"]
    assert len(calls) == 2 and calls[0].url == calls[1].url
    assert calls[0].content == calls[1].content
    assert len(json.loads(calls[0].content)["text"]) <= semantic.MAX_MODEL_CHARACTERS
    assert b"private-fixture" not in calls[0].content
    assert "private" not in caplog.text
    assert failures._value.get() == before_failures + 1
    assert recovered._value.get() == before_recovered + 1


@pytest.mark.parametrize("error,reason", [
    (httpx.ConnectError, "connection_failed"), (httpx.ConnectTimeout, "connect_timeout"),
    (httpx.ReadTimeout, "read_timeout"), (httpx.WriteTimeout, "write_timeout"),
    (httpx.PoolTimeout, "pool_timeout"),
])
def test_transport_failures_are_bounded_and_distinguished(monkeypatch, error, reason):
    calls = []

    def handler(request):
        calls.append(1)
        raise error("private failure", request=request)

    with pytest.raises(semantic.SemanticScannerUnavailable) as caught:
        remote(monkeypatch, handler).assess(ScanRequest(content="normal text"))
    assert len(calls) == 2
    assert caught.value.reason == reason and caught.value.attempts == 2
    assert caught.value.attempt_errors == (reason, reason)
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("status,payload,reason,count", [
    (503, {"detail": {"code": "overloaded"}}, "overloaded", 2),
    (503, {"detail": {"code": "queue_timeout"}}, "queue_timeout", 2),
    (503, {"detail": {"code": "proxy_unavailable", "termination": "sQ"}}, "proxy_queue_timeout", 2),
    (503, {"detail": {"code": "proxy_unavailable", "termination": "SC"}}, "proxy_connection_failed", 2),
    (503, {"detail": {"code": "proxy_unavailable", "termination": []}}, "proxy_unavailable", 2),
    (503, {"detail": {"code": "proxy_unavailable", "termination": "private"}}, "proxy_unavailable", 2),
    (503, {"detail": {"code": "inference_failed"}}, "inference_failed", 1),
    (503, {"detail": {"code": []}}, "unavailable", 2),
    (403, {"detail": "private"}, "http_error", 1),
    (302, {}, "http_error", 1),
    (502, {}, "http_error", 2),
    (200, {"score": .1, "model": "unreviewed"}, "invalid_response", 1),
    (200, {"score": True, "model": semantic.SEMANTIC_MODEL_ID}, "invalid_response", 1),
    (200, [], "invalid_response", 1),
])
def test_untrusted_responses_do_not_change_model_or_cause_unbounded_retries(monkeypatch, status, payload, reason, count):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, json=payload, headers={"Location": "http://untrusted.invalid"})

    with pytest.raises(semantic.SemanticScannerUnavailable) as caught:
        remote(monkeypatch, handler).assess(ScanRequest(content="normal text"))
    assert len(calls) == count and caught.value.reason == reason
    assert all(request.url.host == "controlled.invalid" for request in calls)


def test_real_slow_drip_and_retry_share_one_deadline():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            calls.append(1)
            self.rfile.read(int(self.headers["Content-Length"]))
            if len(calls) == 1:
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                try:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
                time.sleep(.05)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        service = semantic.RemoteSemanticScanner(f"http://127.0.0.1:{server.server_port}", "shadow", .9, .4)
        start = time.monotonic()
        with pytest.raises(semantic.SemanticScannerUnavailable) as caught:
            service.assess(ScanRequest(content="normal text"))
        elapsed = time.monotonic() - start
        assert .3 <= elapsed < .8
        assert caught.value.reason == "deadline_exceeded"
        assert caught.value.attempt_errors == ("unavailable", "deadline_exceeded")
        assert caught.value.attempts == 2 and len(calls) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


@pytest.mark.parametrize("reason", ["overloaded", "proxy_queue_timeout", "proxy_unavailable", "proxy_connection_failed"])
def test_gateway_model_retry_does_not_reexecute_tool(setup_invocation, monkeypatch, reason):
    _, _, headers, payload, tool_calls = setup_invocation
    scores = []

    def handler(request):
        scores.append(request)
        if len(scores) == 1:
            return httpx.Response(503, json={"detail": {"code": reason}})
        return httpx.Response(200, json={"score": .1, "model": semantic.SEMANTIC_MODEL_ID})

    service = remote(monkeypatch, handler)
    monkeypatch.setattr(scanner, "get_semantic_scanner", lambda: service)
    response = client.post("/mcp/tools/call", headers=headers, json=payload)
    assert response.status_code == 200
    assert response.json()["invocation"]["state"] == "succeeded"
    assert len(tool_calls) == 1 and len(scores) == 2


@pytest.mark.parametrize("reason", ["unavailable", "proxy_queue_timeout", "proxy_unavailable", "proxy_connection_failed"])
def test_failed_retry_is_not_reported_as_complete_scan(monkeypatch, reason):
    service = remote(monkeypatch, lambda _: httpx.Response(503, json={"detail": {"code": reason}}))
    monkeypatch.setattr(scanner, "get_semantic_scanner", lambda: service)
    result = scanner.scan_content(ScanRequest(content="normal text"))
    assert result.semantic_assessment.status == "error"
    assert result.semantic_assessment.attempts == 2
    assert result.semantic_assessment.error_reason == reason
    assert result.semantic_assessment.attempt_errors == [reason, reason]
    service.mode = "enforce"
    with pytest.raises(semantic.SemanticScannerUnavailable):
        scanner.scan_content(ScanRequest(content="normal text"))


@pytest.mark.asyncio
async def test_semantic_probes_do_not_wait_for_saturated_scoring_threads(monkeypatch):
    from agentops_guard.semantic_service import app as service

    warm_threads = []

    class ReadyScanner(semantic.SemanticScanner):
        def __init__(self):
            pass

        def warm(self):
            warm_threads.append(threading.get_ident())

    model = ReadyScanner()
    monkeypatch.setattr(service, "get_semantic_scanner", lambda: model)
    limiter = anyio.to_thread.current_default_thread_limiter()
    original_tokens = limiter.total_tokens
    limiter.total_tokens = 1
    entered = threading.Event()
    release = threading.Event()

    def occupy_scoring_pool():
        entered.set()
        release.wait(timeout=3)

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(anyio.to_thread.run_sync, occupy_scoring_pool)
            try:
                with anyio.fail_after(1):
                    while not entered.is_set():
                        await anyio.sleep(.001)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=service.app),
                                             base_url="http://controlled.invalid") as client:
                    with anyio.fail_after(.5):
                        health = await client.get("/healthz")
                        ready = await client.get("/readyz")
                assert health.status_code == ready.status_code == 200
                assert warm_threads and warm_threads[0] != threading.get_ident()
                # Success must not depend on releasing the busy scoring worker.
                assert not release.is_set()
            finally:
                release.set()
    finally:
        limiter.total_tokens = original_tokens


@pytest.mark.asyncio
async def test_semantic_readiness_rechecks_current_scanner_and_warmup(monkeypatch):
    from agentops_guard.semantic_service import app as service

    class ControlledScanner(semantic.SemanticScanner):
        def __init__(self):
            self.fail = False
            self.calls = 0

        def warm(self):
            self.calls += 1
            if self.fail:
                raise semantic.SemanticScannerUnavailable("private failure", reason="warmup_failed")

    initial, replacement = ControlledScanner(), ControlledScanner()
    current = [initial]
    monkeypatch.setattr(service, "get_semantic_scanner", lambda: current[0])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=service.app),
                                base_url="http://controlled.invalid") as client:
        assert (await client.get("/readyz")).status_code == 200
        current[0] = None
        assert (await client.get("/readyz")).status_code == 503
        replacement.fail = True
        current[0] = replacement
        failed = await client.get("/readyz")
        assert failed.status_code == 503
        assert failed.json() == {"detail": {"code": "warmup_failed"}}
        replacement.fail = False
        assert (await client.get("/readyz")).status_code == 200
    assert initial.calls == 1 and replacement.calls == 2


def test_remote_readiness_probes_again_after_success_and_configuration_change(monkeypatch):
    settings = SimpleNamespace(semantic_scanner_mode="disabled", semantic_service_url="http://first.invalid",
                               semantic_scanner_threshold=.9, semantic_service_timeout_seconds=.5)
    status = [200]
    calls = []

    def handler(request):
        calls.append((request.url.host, request.url.path))
        return httpx.Response(status[0])

    real_client = httpx.Client
    monkeypatch.setattr(semantic.httpx, "Client", lambda **kwargs:
        real_client(**kwargs, transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(semantic, "get_settings", lambda: settings)
    assert semantic.semantic_scanner_ready() is True
    assert calls == []  # A previous disabled mode must not cache later readiness.
    settings.semantic_scanner_mode = "shadow"
    assert semantic.semantic_scanner_ready() is True
    status[0] = 503
    with pytest.raises(semantic.SemanticScannerUnavailable):
        semantic.semantic_scanner_ready()
    settings.semantic_service_url = "http://replacement.invalid"
    status[0] = 200
    assert semantic.semantic_scanner_ready() is True
    assert calls == [("first.invalid", "/readyz"), ("first.invalid", "/readyz"),
                     ("replacement.invalid", "/readyz")]


@pytest.mark.asyncio
async def test_semantic_readiness_reports_model_initialization_failure_as_unavailable(monkeypatch):
    from agentops_guard.semantic_service import app as service

    def invalid_model():
        raise semantic.SemanticScannerUnavailable("private model path")

    monkeypatch.setattr(service, "get_semantic_scanner", invalid_model)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=service.app),
                                base_url="http://controlled.invalid") as client:
        response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "unavailable"}}
