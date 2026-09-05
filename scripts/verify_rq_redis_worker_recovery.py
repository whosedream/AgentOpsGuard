from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from multiprocessing import get_context
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from typing import Any
from uuid import uuid4

from redis import Redis
from rq import Queue, Worker

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.models import BackgroundJob, OutboxEvent
from agentops_guard.backend.services.jobs import (
    create_job,
    dispatch_outbox_batch,
    reconcile_background_job_leases,
)


def _run_worker(queue_name: str, marker_path: str, mode: str) -> None:
    os.setsid()
    from agentops_guard.backend.services import jobs

    marker = Path(marker_path)
    if mode == "block":

        def block_payload(db: Any, row: BackgroundJob) -> dict[str, Any]:
            marker.write_text("payload_started", encoding="utf-8")
            time.sleep(300)
            return {}

        jobs._execute_payload = block_payload
    elif mode == "complete":

        def complete_payload(db: Any, row: BackgroundJob) -> dict[str, Any]:
            marker.write_text("executed_once", encoding="utf-8")
            return {"verified": True}

        jobs._execute_payload = complete_payload
    else:
        raise ValueError("unsupported worker mode")

    connection = jobs.redis_connection()
    worker = Worker(
        [Queue(queue_name, connection=connection)],
        connection=connection,
        name=f"agentops-verification-{mode}-{os.getpid()}",
    )
    worker.work(burst=True, logging_level="WARNING")


def _wait_for_marker(marker: Path, process: Any) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if marker.exists():
            return
        if not process.is_alive():
            raise RuntimeError(f"RQ worker exited before payload start: {process.exitcode}")
        time.sleep(0.05)
    raise RuntimeError("RQ worker did not reach payload start")


def _worker_session_members(session_id: int) -> list[int]:
    completed = subprocess.run(
        ["ps", "--sid", str(session_id), "-o", "pid="],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    return [int(value) for value in completed.stdout.split()]


def _signal_worker_session(session_id: int, signal_number: int) -> None:
    for pid in _worker_session_members(session_id):
        try:
            os.kill(pid, signal_number)
        except ProcessLookupError:
            pass


def _stop_worker_session(process: Any) -> None:
    session_id = os.getsid(process.pid)
    if session_id != process.pid:
        raise RuntimeError("refusing to stop an unexpected worker session")
    _signal_worker_session(session_id, signal.SIGTERM)
    process.join(timeout=10)
    deadline = time.monotonic() + 5
    while _worker_session_members(session_id) and time.monotonic() < deadline:
        time.sleep(0.05)
    remaining = _worker_session_members(session_id)
    if remaining:
        _signal_worker_session(session_id, signal.SIGKILL)
        process.join(timeout=5)
    if process.is_alive() or _worker_session_members(session_id):
        raise RuntimeError("RQ worker session did not stop")


def main() -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("This verification requires PostgreSQL")

    suffix = uuid4().hex
    project_id = f"rq_recovery_project_{suffix}"
    queue_name = "default"
    dispatcher_id = f"verification-dispatcher-{suffix}"
    db = SessionLocal()
    try:
        job = create_job(db, project_id, "replay", {})
        original_event = db.get(OutboxEvent, f"outbox_{job.id}")
        assert original_event is not None
        original_event.payload = {"job_id": job.id, "queue_name": queue_name}
        db.commit()
        job_id = job.id
        original_event_id = original_event.id
    finally:
        db.close()

    connection = Redis.from_url(os.environ["AGENTOPS_REDIS_URL"])
    queue = Queue(queue_name, connection=connection)

    with tempfile.TemporaryDirectory(prefix="agentops-rq-recovery-") as temp_dir:
        crash_marker = Path(temp_dir) / "crash-stage"
        success_marker = Path(temp_dir) / "successful-side-effect"

        db = SessionLocal()
        try:
            if dispatch_outbox_batch(db, dispatcher_id=dispatcher_id) != 1:
                raise RuntimeError("initial outbox event was not delivered")
        finally:
            db.close()

        worker = get_context("fork").Process(
            target=_run_worker,
            args=(queue_name, str(crash_marker), "block"),
        )
        worker.start()
        _wait_for_marker(crash_marker, worker)
        _stop_worker_session(worker)

        db = SessionLocal()
        try:
            row = db.get(BackgroundJob, job_id)
            if row is None or row.status != "running" or row.attempts != 1:
                raise RuntimeError("terminated RQ worker did not leave a recoverable lease")
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()
            if reconcile_background_job_leases(db) != 1:
                raise RuntimeError("expired RQ worker lease was not recovered")
            db.commit()
            db.refresh(row)
            retry_event_id = f"outbox_retry_{job_id}_{row.attempts}"
            retry_event = db.get(OutboxEvent, retry_event_id)
            if row.status != "pending" or retry_event is None:
                raise RuntimeError("recovery did not create a durable retry event")
            retry_available_at = retry_event.available_at
        finally:
            db.close()

        if not isinstance(retry_available_at, datetime):
            raise RuntimeError("retry event availability timestamp is invalid")
        retry_delay = (retry_available_at - datetime.now(UTC)).total_seconds()
        if retry_delay > 0:
            time.sleep(retry_delay + 0.1)

        db = SessionLocal()
        try:
            retry_delivery_count = dispatch_outbox_batch(db, dispatcher_id=dispatcher_id)
            if retry_delivery_count != 1:
                db.expire_all()
                retry_event = db.get(OutboxEvent, retry_event_id)
                raise RuntimeError(
                    "retry event was not delivered: "
                    f"status={getattr(retry_event, 'status', None)}, "
                    f"attempts={getattr(retry_event, 'attempts', None)}, "
                    f"error={getattr(retry_event, 'last_error_code', None)}, "
                    f"redis_ready={bool(connection.ping())}"
                )
            retry_event = db.get(OutboxEvent, retry_event_id)
            assert retry_event is not None
            retry_event.status = "pending"
            retry_event.delivered_at = None
            retry_event.available_at = datetime.now(UTC)
            db.commit()
            if dispatch_outbox_batch(db, dispatcher_id=dispatcher_id) != 1:
                raise RuntimeError("duplicate retry delivery was not reconciled")
        finally:
            db.close()

        queued_ids = queue.get_job_ids()
        if queued_ids.count(retry_event_id) != 1:
            raise RuntimeError("stable RQ job ID did not suppress duplicate queue entries")

        worker = get_context("fork").Process(
            target=_run_worker,
            args=(queue_name, str(success_marker), "complete"),
        )
        worker.start()
        worker.join(timeout=30)
        if worker.is_alive():
            _stop_worker_session(worker)
            raise RuntimeError("recovery worker did not finish")
        if worker.exitcode != 0:
            raise RuntimeError(f"recovery worker failed: {worker.exitcode}")

        db = SessionLocal()
        try:
            row = db.get(BackgroundJob, job_id)
            if (
                row is None
                or row.status != "completed"
                or row.attempts != 2
                or row.result != {"verified": True}
            ):
                raise RuntimeError("recovered job did not complete exactly once")
            if success_marker.read_text(encoding="utf-8") != "executed_once":
                raise RuntimeError("successful payload execution marker is invalid")
            result = {
                "real_postgresql": True,
                "real_redis": True,
                "real_rq_worker": True,
                "worker_process_group_terminated": True,
                "expired_lease_recovered": True,
                "duplicate_delivery_suppressed": True,
                "successful_attempts": row.attempts,
                "final_status": row.status,
            }
            db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete(
                synchronize_session=False
            )
            db.delete(row)
            db.commit()
        finally:
            db.close()

    for rq_job_id in (original_event_id, retry_event_id):
        rq_job = connection.hget(f"rq:job:{rq_job_id}", "status")
        if rq_job is not None:
            connection.delete(f"rq:job:{rq_job_id}")
    connection.delete(queue.key)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
