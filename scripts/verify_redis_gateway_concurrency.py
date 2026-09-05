from __future__ import annotations

import json
from multiprocessing import Event, get_context
import os
import time
from typing import Any

from redis import Redis

from agentops_guard.gateway.concurrency import GatewayCapacityExceeded, server_call_slot


def _hold_slot(entered: Any, release: Any, server_id: str, lease_seconds: float) -> None:
    with server_call_slot(
        server_id,
        limit=1,
        wait_seconds=0,
        backend="redis",
        redis_url=os.environ["AGENTOPS_REDIS_URL"],
        lease_seconds=lease_seconds,
    ):
        entered.set()
        release.wait(timeout=30)


def _start_holder(server_id: str, lease_seconds: float) -> tuple[Any, Any, Any]:
    context = get_context("fork")
    entered: Event = context.Event()
    release: Event = context.Event()
    process = context.Process(
        target=_hold_slot,
        args=(entered, release, server_id, lease_seconds),
    )
    process.start()
    if not entered.wait(timeout=10):
        process.terminate()
        process.join(timeout=5)
        raise RuntimeError("holder process did not acquire the distributed slot")
    return process, entered, release


def main() -> None:
    redis_url = os.environ["AGENTOPS_REDIS_URL"]
    connection = Redis.from_url(redis_url)
    if not connection.ping():
        raise RuntimeError("Redis is unavailable")
    server_id = f"shared-server-{os.getpid()}"

    holder, _entered, release = _start_holder(server_id, 5)
    try:
        try:
            with server_call_slot(
                server_id,
                limit=1,
                wait_seconds=0,
                backend="redis",
                redis_url=redis_url,
                lease_seconds=5,
            ):
                raise RuntimeError("a second process acquired an occupied slot")
        except GatewayCapacityExceeded:
            pass

        with server_call_slot(
            f"other-{server_id}",
            limit=1,
            wait_seconds=0,
            backend="redis",
            redis_url=redis_url,
            lease_seconds=5,
        ):
            pass
    finally:
        release.set()
        holder.join(timeout=10)
        if holder.is_alive():
            holder.kill()
            holder.join(timeout=5)
    if holder.exitcode != 0:
        raise RuntimeError(f"slot holder failed: {holder.exitcode}")

    with server_call_slot(
        server_id,
        limit=1,
        wait_seconds=0,
        backend="redis",
        redis_url=redis_url,
        lease_seconds=5,
    ):
        pass

    crashed, _entered, _release = _start_holder(server_id, 0.5)
    crashed.kill()
    crashed.join(timeout=5)
    if crashed.is_alive():
        raise RuntimeError("crashed slot holder did not stop")
    time.sleep(0.6)
    with server_call_slot(
        server_id,
        limit=1,
        wait_seconds=0,
        backend="redis",
        redis_url=redis_url,
        lease_seconds=1,
    ):
        pass

    connection.close()
    print(
        json.dumps(
            {
                "real_redis": True,
                "cross_process_limit": True,
                "different_servers_isolated": True,
                "release_reopens_capacity": True,
                "crash_lease_expires": True,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
