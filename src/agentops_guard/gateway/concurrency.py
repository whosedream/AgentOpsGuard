from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
from secrets import token_hex
from threading import BoundedSemaphore, Lock
import time
from typing import Iterator

from redis import Redis
from redis.exceptions import RedisError


class GatewayCapacityExceeded(RuntimeError):
    pass


class GatewayCapacityUnavailable(RuntimeError):
    pass


_registry_lock = Lock()
_server_slots: dict[tuple[str, int], BoundedSemaphore] = {}
_ACQUIRE_SLOT = """
local redis_time = redis.call('TIME')
local now_ms = redis_time[1] * 1000 + math.floor(redis_time[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
  return 0
end
redis.call('ZADD', KEYS[1], now_ms + tonumber(ARGV[1]), ARGV[2])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]))
return 1
"""
_RELEASE_SLOT = "return redis.call('ZREM', KEYS[1], ARGV[1])"


@contextmanager
def server_call_slot(
    server_id: str,
    *,
    limit: int,
    wait_seconds: float,
    backend: str = "local",
    redis_url: str | None = None,
    lease_seconds: float = 60.0,
) -> Iterator[None]:
    if limit < 1:
        raise ValueError("Gateway concurrency limit must be positive")
    if backend == "redis":
        if redis_url is None:
            raise GatewayCapacityUnavailable("Distributed capacity store is unavailable")
        with _redis_server_call_slot(
            server_id,
            limit=limit,
            wait_seconds=wait_seconds,
            lease_seconds=lease_seconds,
            redis_url=redis_url,
        ):
            yield
        return
    if backend != "local":
        raise ValueError("Unsupported Gateway concurrency backend")
    key = (server_id, limit)
    with _registry_lock:
        semaphore = _server_slots.setdefault(key, BoundedSemaphore(limit))
    if not semaphore.acquire(timeout=wait_seconds):
        raise GatewayCapacityExceeded(f"MCP server capacity exceeded: {server_id}")
    try:
        yield
    finally:
        semaphore.release()


@contextmanager
def _redis_server_call_slot(
    server_id: str,
    *,
    limit: int,
    wait_seconds: float,
    lease_seconds: float,
    redis_url: str,
) -> Iterator[None]:
    if lease_seconds <= 0:
        raise ValueError("Gateway concurrency lease must be positive")
    key = f"agentops:gateway-capacity:{sha256(server_id.encode()).hexdigest()}"
    token = token_hex(16)
    lease_ms = max(1, int(lease_seconds * 1000))
    deadline = time.monotonic() + wait_seconds
    connection = Redis.from_url(
        redis_url,
        socket_connect_timeout=max(0.1, min(1.0, wait_seconds or 0.1)),
        socket_timeout=max(0.1, min(1.0, wait_seconds or 0.1)),
    )
    acquired = False
    try:
        while True:
            try:
                acquired = bool(
                    connection.eval(
                        _ACQUIRE_SLOT,
                        1,
                        key,
                        lease_ms,
                        token,
                        limit,
                        lease_ms * 2,
                    )
                )
            except RedisError as exc:
                raise GatewayCapacityUnavailable(
                    "Distributed capacity store is unavailable"
                ) from exc
            if acquired:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GatewayCapacityExceeded("MCP server capacity exceeded")
            time.sleep(min(0.05, remaining))
        yield
    finally:
        if acquired:
            try:
                connection.eval(_RELEASE_SLOT, 1, key, token)
            except RedisError:
                pass
        connection.close()
