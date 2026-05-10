from datetime import UTC, datetime
from typing import Any

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue
from rq.job import Job as RqJob
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import BackgroundJob
from agentops_guard.backend.schemas import EvalRunCreate, ReplayCreate
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.eval import run_eval
from agentops_guard.backend.services.mcp_refresh import refresh_mcp_tools
from agentops_guard.backend.services.replay import create_replay


class QueueUnavailable(RuntimeError):
    pass


def redis_connection() -> Redis:
    return Redis.from_url(get_settings().redis_url)


def assert_redis_available() -> None:
    try:
        redis_connection().ping()
    except RedisError as exc:
        raise QueueUnavailable(str(exc)) from exc


def create_job(db: Session, project_id: str, kind: str, payload: dict[str, Any]) -> BackgroundJob:
    row = BackgroundJob(id=new_id("job"), project_id=project_id, kind=kind, payload=payload)
    db.add(row)
    db.flush()
    return row


def enqueue_job(db: Session, row: BackgroundJob, queue_name: str = "default") -> BackgroundJob:
    assert_redis_available()
    queue = Queue(queue_name, connection=redis_connection())
    rq_job = queue.enqueue("agentops_guard.backend.services.jobs.execute_job", row.id, job_timeout=600)
    row.rq_job_id = rq_job.id
    db.flush()
    return row


def execute_job(job_id: str) -> dict[str, Any]:
    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, job_id)
        if row is None:
            raise ValueError(f"Job not found: {job_id}")
        row.status = "running"
        row.attempts = (row.attempts or 0) + 1
        row.started_at = datetime.now(UTC)
        db.commit()
        try:
            result = _execute_payload(db, row)
            row.status = "completed"
            row.result = result
            row.error = None
            row.finished_at = datetime.now(UTC)
            db.commit()
            return result
        except Exception as exc:
            row.status = "failed"
            row.error = str(exc)
            row.finished_at = datetime.now(UTC)
            db.commit()
            raise
    finally:
        db.close()


def _execute_payload(db: Session, row: BackgroundJob) -> dict[str, Any]:
    if row.kind == "replay":
        replay = create_replay(db, ReplayCreate(**row.payload))
        db.flush()
        return {"replay_id": replay.id, "status": replay.status}
    if row.kind == "eval_run":
        eval_run = run_eval(db, EvalRunCreate(**row.payload))
        db.flush()
        return {"eval_run_id": eval_run.id, "status": eval_run.status, "passed": eval_run.passed}
    if row.kind == "mcp_refresh":
        return refresh_mcp_tools(db, str(row.payload.get("server_id")))
    raise ValueError(f"Unsupported job kind: {row.kind}")


def rq_job_status(rq_job_id: str | None) -> str | None:
    if not rq_job_id:
        return None
    try:
        return RqJob.fetch(rq_job_id, connection=redis_connection()).get_status(refresh=True).value
    except Exception:
        return None
