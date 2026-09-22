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


def test_expired_capacity_wait_does_not_make_another_reservation(monkeypatch):
    clock = [0.0]
    calls = []

    class BusyRedis:
        def eval(self, script, *_args):
            calls.append(script)
            clock[0] = 0.99
            return 0

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(concurrency.Redis, "from_url", lambda *a, **kw: BusyRedis())
    monkeypatch.setattr(concurrency.time, "monotonic", lambda: clock[0])
    # Simulate the host resuming after the deadline, not a longer wait setting.
    monkeypatch.setattr(concurrency.time, "sleep", lambda _wait: clock.__setitem__(0, 1.1))
    with pytest.raises(GatewayCapacityExceeded):
        with server_call_slot("deadline", limit=1, wait_seconds=1, backend="redis",
                              redis_url="redis://controlled.invalid"):
            pytest.fail("expired wait must not dispatch a tool")
    assert calls == [concurrency._ACQUIRE_SLOT, "closed"]


@pytest.mark.parametrize("wait_seconds,dispatch_allowed", [(1, False), (0, True)])
def test_late_reservation_is_released_and_zero_wait_keeps_one_attempt(
    monkeypatch, wait_seconds, dispatch_allowed,
):
    clock = [0.0]
    calls = []

    class LateRedis:
        def eval(self, script, *_args):
            calls.append(script)
            clock[0] = 1.1
            return 1

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(concurrency.Redis, "from_url", lambda *a, **kw: LateRedis())
    monkeypatch.setattr(concurrency.time, "monotonic", lambda: clock[0])
    dispatched = []

    def invoke():
        with server_call_slot("late-reply", limit=1, wait_seconds=wait_seconds,
                              backend="redis", redis_url="redis://controlled.invalid"):
            dispatched.append(True)

    if dispatch_allowed:
        invoke()
    else:
        with pytest.raises(GatewayCapacityExceeded):
            invoke()
    assert bool(dispatched) is dispatch_allowed
    assert calls == [concurrency._ACQUIRE_SLOT, concurrency._RELEASE_SLOT, "closed"]
