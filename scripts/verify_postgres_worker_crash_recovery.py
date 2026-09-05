from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from multiprocessing import get_context
from pathlib import Path
import tempfile
import time
from typing import Any
from uuid import uuid4

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.models import BackgroundJob, OutboxEvent
from agentops_guard.backend.services.jobs import reconcile_background_job_leases


def _execute_until_killed(job_id: str, marker_path: str, stage: str) -> None:
    from agentops_guard.backend.services import jobs

    marker = Path(marker_path)
    if stage == "during_payload":

        def wait_in_payload(db: Any, row: BackgroundJob) -> dict[str, Any]:
            marker.write_text(stage, encoding="utf-8")
            time.sleep(300)
            return {}

        jobs._execute_payload = wait_in_payload
    elif stage == "after_payload_before_commit":

        def finish_payload(db: Any, row: BackgroundJob) -> dict[str, Any]:
            return {"completed": True}

        class BlockingHeartbeat:
            def join(self, timeout: float | None = None) -> None:
                marker.write_text(stage, encoding="utf-8")
                time.sleep(300)

            def is_alive(self) -> bool:
                return False

        def blocked_heartbeat(job_id: str, claimant: str) -> tuple[Any, Any, BlockingHeartbeat]:
            from threading import Event

            return Event(), Event(), BlockingHeartbeat()

        jobs._execute_payload = finish_payload
        jobs._start_job_heartbeat = blocked_heartbeat
    else:
        raise ValueError("unsupported crash stage")
    jobs.execute_job(job_id)


def _wait_for_marker(marker: Path, process: Any) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if marker.exists():
            return
        if not process.is_alive():
            raise RuntimeError(f"worker exited before reaching crash point: {process.exitcode}")
        time.sleep(0.05)
    raise RuntimeError("worker did not reach crash point")


def _verify_stage(stage: str) -> dict[str, Any]:
    suffix = uuid4().hex
    job_id = f"crash_{suffix[:24]}"
    project_id = f"crash_project_{suffix}"
    db = SessionLocal()
    try:
        db.add(
            BackgroundJob(
                id=job_id,
                project_id=project_id,
                kind="replay",
                status="pending",
                payload={},
            )
        )
        db.commit()
    finally:
        db.close()

    with tempfile.TemporaryDirectory(prefix="agentops-crash-") as temp_dir:
        marker = Path(temp_dir) / "reached"
        process = get_context("spawn").Process(
            target=_execute_until_killed,
            args=(job_id, str(marker), stage),
        )
        process.start()
        _wait_for_marker(marker, process)
        process.terminate()
        process.join(timeout=10)
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        if process.exitcode is None:
            raise RuntimeError("worker process did not stop")

    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, job_id)
        if row is None or row.status != "running" or row.attempts != 1:
            raise RuntimeError("killed worker did not leave a recoverable running lease")
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()

        recovered = reconcile_background_job_leases(db)
        db.commit()
        db.expire_all()
        row = db.get(BackgroundJob, job_id)
        if (
            recovered != 1
            or row is None
            or row.status != "pending"
            or row.error != "worker_lease_expired"
            or row.lease_owner is not None
        ):
            raise RuntimeError("expired worker lease was not recovered safely")
        retry_event = db.get(OutboxEvent, f"outbox_retry_{job_id}_{row.attempts}")
        if retry_event is None or retry_event.status != "pending":
            raise RuntimeError("worker recovery did not create a durable retry event")
        result = {
            "stage": stage,
            "process_terminated": True,
            "lease_recovered": True,
            "retry_status": row.status,
            "attempts": row.attempts,
        }
        db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete(
            synchronize_session=False
        )
        db.delete(row)
        db.commit()
        return result
    finally:
        db.close()


def main() -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("This verification requires PostgreSQL")
    results = [
        _verify_stage("during_payload"),
        _verify_stage("after_payload_before_commit"),
    ]
    print(json.dumps({"results": results}, separators=(",", ":")))


if __name__ == "__main__":
    main()
