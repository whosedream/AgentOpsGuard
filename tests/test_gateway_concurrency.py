import threading

import pytest
from redis.exceptions import RedisError

from agentops_guard.gateway import concurrency
from agentops_guard.gateway.concurrency import (
    GatewayCapacityExceeded,
    GatewayCapacityUnavailable,
    server_call_slot,
)


def test_server_concurrency_limit_rejects_excess_work_and_recovers():
    entered = threading.Event()
    release = threading.Event()

    def hold_slot():
        with server_call_slot("limited-server", limit=1, wait_seconds=0):
            entered.set()
            release.wait(timeout=2)

    thread = threading.Thread(target=hold_slot)
    thread.start()
    assert entered.wait(timeout=1)
    try:
        with pytest.raises(GatewayCapacityExceeded):
            with server_call_slot("limited-server", limit=1, wait_seconds=0):
                pass
    finally:
        release.set()
        thread.join(timeout=2)

    with server_call_slot("limited-server", limit=1, wait_seconds=0):
        pass


def test_distributed_concurrency_fails_closed_when_redis_is_unavailable(monkeypatch):
    class DownRedis:
        def eval(self, *_args, **_kwargs):
            raise RedisError("unavailable")

        def close(self):
            pass

    monkeypatch.setattr(concurrency.Redis, "from_url", lambda *_args, **_kwargs: DownRedis())

    with pytest.raises(GatewayCapacityUnavailable, match="capacity store is unavailable"):
        with server_call_slot(
            "shared-server",
            limit=1,
            wait_seconds=0,
            backend="redis",
            redis_url="redis://coordination.invalid/0",
        ):
            pass


def test_unknown_concurrency_backend_is_rejected():
    with pytest.raises(ValueError, match="Unsupported Gateway concurrency backend"):
        with server_call_slot(
            "shared-server",
            limit=1,
            wait_seconds=0,
            backend="unknown",
        ):
            pass
