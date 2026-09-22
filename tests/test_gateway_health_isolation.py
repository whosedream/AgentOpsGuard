"""Health is not tool capacity; readiness still checks current dependencies."""

import asyncio
from collections import Counter
import threading

import anyio
from fastapi import HTTPException
import httpx
import pytest

from agentops_guard.backend.services.opa import OpaUnavailable
from agentops_guard.backend.services.semantic_scanner import SemanticScannerUnavailable
from agentops_guard.gateway import app as gateway


@pytest.mark.asyncio
async def test_gateway_probes_do_not_wait_for_saturated_tool_threads(monkeypatch):
    checks = []
    monkeypatch.setattr(gateway, "check_database_ready", lambda _engine: checks.append("database"))
    monkeypatch.setattr(gateway, "semantic_scanner_ready", lambda: checks.append("semantic"))
    monkeypatch.setattr(gateway, "check_opa_health", lambda: checks.append("opa"))
    limiter = anyio.to_thread.current_default_thread_limiter()
    original_tokens = limiter.total_tokens
    limiter.total_tokens = 1
    entered, release = threading.Event(), threading.Event()

    def occupy_tool_worker():
        entered.set()
        release.wait(timeout=3)

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(anyio.to_thread.run_sync, occupy_tool_worker)
            try:
                with anyio.fail_after(1):
                    while not entered.is_set():
                        await anyio.sleep(.001)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app),
                                             base_url="http://controlled.invalid") as client:
                    with anyio.fail_after(.5):
                        health = await client.get("/healthz")
                        ready = await client.get("/readyz")
                assert health.json() == {"status": "ok"}
                assert ready.json() == {"status": "ready"}
                assert health.status_code == ready.status_code == 200
                assert Counter(checks) == Counter(["database", "semantic", "opa"])
                assert not release.is_set()
            finally:
                release.set()
    finally:
        limiter.total_tokens = original_tokens


@pytest.mark.asyncio
@pytest.mark.parametrize("dependency,detail", [
    ("database", "Database temporarily unavailable"),
    ("semantic", "Semantic scanner unavailable"),
    ("opa", "OPA unavailable"),
])
async def test_gateway_readiness_rechecks_failures_after_success(monkeypatch, dependency, detail):
    unavailable = [False]
    checks = []

    def check(name):
        checks.append(name)
        if name == dependency and unavailable[0]:
            if name == "database":
                raise HTTPException(503, "Database temporarily unavailable")
            if name == "semantic":
                raise SemanticScannerUnavailable("private semantic failure")
            raise OpaUnavailable("private policy failure")

    monkeypatch.setattr(gateway, "check_database_ready", lambda _engine: check("database"))
    monkeypatch.setattr(gateway, "semantic_scanner_ready", lambda: check("semantic"))
    monkeypatch.setattr(gateway, "check_opa_health", lambda: check("opa"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app),
                                base_url="http://controlled.invalid") as client:
        assert (await client.get("/readyz")).status_code == 200
        unavailable[0] = True
        failed = await client.get("/readyz")
        assert failed.status_code == 503
        assert failed.json() == {"detail": detail}
        assert "private" not in failed.text
        # Liveness says the process responds, not that dependencies are healthy.
        assert (await client.get("/healthz")).status_code == 200
        unavailable[0] = False
        assert (await client.get("/readyz")).status_code == 200
    assert checks.count(dependency) == 3


@pytest.mark.asyncio
async def test_gateway_probes_run_independently_and_coalesce_overlapping_waiters(monkeypatch):
    entered = {name: threading.Event() for name in ("database", "semantic", "opa")}
    release = threading.Event()
    calls = Counter()

    def check(name):
        calls[name] += 1
        entered[name].set()
        assert release.wait(3), "test must release each bounded probe"

    monkeypatch.setattr(gateway, "check_database_ready", lambda _engine: check("database"))
    monkeypatch.setattr(gateway, "semantic_scanner_ready", lambda: check("semantic"))
    monkeypatch.setattr(gateway, "check_opa_health", lambda: check("opa"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app),
                                base_url="http://controlled.invalid") as client:
        requests = [asyncio.create_task(client.get("/readyz")) for _ in range(12)]
        try:
            with anyio.fail_after(1):
                while not all(value.is_set() for value in entered.values()):
                    await anyio.sleep(.001)
            # With the former sequential probe, semantic/OPA cannot start until
            # the DB releases. Twelve waiters must still issue only three checks.
            assert calls == Counter({name: 1 for name in entered})
            assert not any(request.done() for request in requests)
            assert (await client.get("/healthz")).status_code == 200
        finally:
            release.set()
            replies = await asyncio.gather(*requests)
        assert all(reply.status_code == 200 for reply in replies)
        # A new check after completion is fresh, not a positive-health cache.
        assert (await client.get("/readyz")).status_code == 200
        assert calls == Counter({name: 2 for name in entered})


@pytest.mark.asyncio
async def test_cancelled_probe_keeps_one_round_and_reports_real_failure(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def blocked_semantic():
        calls.append(1)
        entered.set()
        assert release.wait(3)
        raise SemanticScannerUnavailable("private model endpoint")

    monkeypatch.setattr(gateway, "check_database_ready", lambda _engine: None)
    monkeypatch.setattr(gateway, "semantic_scanner_ready", blocked_semantic)
    monkeypatch.setattr(gateway, "check_opa_health", lambda: None)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app),
                                base_url="http://controlled.invalid") as client:
        first = asyncio.create_task(client.get("/readyz"))
        second = None
        try:
            with anyio.fail_after(1):
                while not entered.is_set():
                    await anyio.sleep(.001)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            second = asyncio.create_task(client.get("/readyz"))
            await anyio.sleep(.02)
            assert calls == [1]
            assert not second.done()
        finally:
            release.set()
            if second is not None:
                reply = await second
            if not first.done():
                await first
        assert reply.status_code == 503
        assert reply.json() == {"detail": "Semantic scanner unavailable"}
        assert "private" not in reply.text
        monkeypatch.setattr(gateway, "semantic_scanner_ready", lambda: None)
        assert (await client.get("/readyz")).status_code == 200


@pytest.mark.asyncio
async def test_gateway_probe_programming_error_is_not_hidden(monkeypatch):
    monkeypatch.setattr(gateway, "check_database_ready", lambda _engine: None)
    monkeypatch.setattr(gateway, "semantic_scanner_ready", lambda: None)

    def broken():
        raise RuntimeError("broken health integration")

    monkeypatch.setattr(gateway, "check_opa_health", broken)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app),
                                base_url="http://controlled.invalid") as client:
        with pytest.raises(RuntimeError, match="broken health integration"):
            await client.get("/readyz")
