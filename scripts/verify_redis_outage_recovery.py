from __future__ import annotations

from datetime import UTC, datetime
import json
from multiprocessing import get_context
import os
import re
import subprocess
import time
from typing import Any
from uuid import uuid4

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue, Worker

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.models import BackgroundJob, OutboxEvent
from agentops_guard.backend.services.jobs import create_job, dispatch_outbox_batch


def _set_redis_container_state(container_name: str, state: str) -> None:
    if not re.fullmatch(r"agentops-redis-outage-[A-Za-z0-9_-]+", container_name):
        raise RuntimeError("refusing to control an unexpected Redis container")
    if state not in {"start", "stop"}:
        raise RuntimeError("unsupported Redis container state")
    command = ["docker", state]
    if state == "stop":
        command.extend(["--time", "2"])
    command.append(container_name)
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_for_redis(redis_url: str) -> Redis:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        connection = Redis.from_url(redis_url)
        try:
            if connection.ping():
                return connection
        except RedisError:
            connection.connection_pool.disconnect()
        time.sleep(0.1)
    raise RuntimeError("Redis did not recover")


def _wait_until_available(available_at: datetime) -> None:
    delay = (available_at - datetime.now(UTC)).total_seconds()
    if delay > 0:
        time.sleep(delay + 0.1)


def _run_completion_worker(queue_name: str) -> None:
    from agentops_guard.backend.services import jobs

    def complete_payload(db: Any, row: BackgroundJob) -> dict[str, Any]:
        return {"recovered_after_redis_outage": True}

    jobs._execute_payload = complete_payload
    connection = jobs.redis_connection()
    worker = Worker(
        [Queue(queue_name, connection=connection)],
        connection=connection,
        name=f"agentops-redis-recovery-{os.getpid()}",
    )
    worker.work(burst=True, logging_level="WARNING")


def main() -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("This verification requires PostgreSQL")
    container_name = os.environ.get("AGENTOPS_TEST_REDIS_CONTAINER", "")
    if not container_name:
        raise RuntimeError("AGENTOPS_TEST_REDIS_CONTAINER is required")
    redis_url = os.environ["AGENTOPS_REDIS_URL"]
    connection = _wait_for_redis(redis_url)

    suffix = uuid4().hex
    project_id = f"redis_outage_project_{suffix}"
    dispatcher_id = f"redis-outage-dispatcher-{suffix}"
    queue_name = "default"
    db = SessionLocal()
    try:
        job = create_job(db, project_id, "replay", {})
        event = db.get(OutboxEvent, f"outbox_{job.id}")
        assert event is not None
        event.payload = {"job_id": job.id, "queue_name": queue_name}
        db.commit()
        job_id = job.id
        event_id = event.id
    finally:
        db.close()

    _set_redis_container_state(container_name, "stop")
    try:
        db = SessionLocal()
        try:
            delivered_while_down = dispatch_outbox_batch(
                db,
                dispatcher_id=dispatcher_id,
            )
        finally:
            db.close()

        db = SessionLocal()
        try:
            event = db.get(OutboxEvent, event_id)
            job = db.get(BackgroundJob, job_id)
            if (
                delivered_while_down != 0
                or event is None
                or event.status != "pending"
                or event.last_error_code != "redis_unavailable"
                or job is None
                or job.status != "pending"
                or job.rq_job_id is not None
            ):
                raise RuntimeError("Redis outage did not preserve the pending database job")
            available_at = event.available_at
        finally:
            db.close()
    finally:
        _set_redis_container_state(container_name, "start")

    connection = _wait_for_redis(redis_url)
    if not isinstance(available_at, datetime):
        raise RuntimeError("outbox retry timestamp is invalid")
    _wait_until_available(available_at)

    db = SessionLocal()
    try:
        if dispatch_outbox_batch(db, dispatcher_id=dispatcher_id) != 1:
            raise RuntimeError("pending outbox event was not delivered after Redis recovery")
    finally:
        db.close()

    worker = get_context("fork").Process(
        target=_run_completion_worker,
        args=(queue_name,),
    )
    worker.start()
    worker.join(timeout=30)
    if worker.is_alive():
        worker.terminate()
        worker.join(timeout=5)
        raise RuntimeError("recovery worker did not finish")
    if worker.exitcode != 0:
        raise RuntimeError(f"recovery worker failed: {worker.exitcode}")

    db = SessionLocal()
    try:
        event = db.get(OutboxEvent, event_id)
        job = db.get(BackgroundJob, job_id)
        if (
            event is None
            or event.status != "delivered"
            or event.attempts != 2
            or job is None
            or job.status != "completed"
            or job.result != {"recovered_after_redis_outage": True}
        ):
            raise RuntimeError("job did not complete after Redis recovery")
        result = {
            "real_postgresql": True,
            "real_redis_stopped": True,
            "database_job_preserved": True,
            "outbox_retried_after_recovery": True,
            "real_rq_worker_completed": True,
            "final_status": job.status,
        }
        db.delete(event)
        db.delete(job)
        db.commit()
    finally:
        db.close()

    connection.delete(Queue(queue_name, connection=connection).key)
    connection.delete(f"rq:job:{event_id}")
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
