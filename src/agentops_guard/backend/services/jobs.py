from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from typing import Any

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue, get_current_job
from rq.exceptions import DuplicateJobError, NoSuchJobError
from rq.job import Job as RqJob
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import BackgroundJob, ExecutionRequest, OutboxEvent
from agentops_guard.backend.observability import (
    JOB_HEARTBEAT_FAILURES_COUNTER,
    JOB_LEASE_RECOVERIES_COUNTER,
)
from agentops_guard.backend.schemas import EvalRunCreate, ReplayCreate
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import new_id, redact_value
from agentops_guard.backend.services.eval import run_eval
from agentops_guard.backend.services.mcp_refresh import refresh_mcp_tools
from agentops_guard.backend.services.replay import create_replay


class QueueUnavailable(RuntimeError):
    pass


class JobAlreadyClaimed(RuntimeError):
    pass


class JobLeaseLost(RuntimeError):
    pass


MAX_JOB_ATTEMPTS = 3
JOB_LEASE_SECONDS = 660
JOB_HEARTBEAT_SECONDS = 60.0
RETRYABLE_JOB_KINDS = {"eval_run", "mcp_refresh", "replay"}


def redis_connection() -> Redis:
    return Redis.from_url(get_settings().redis_url)


def assert_redis_available() -> None:
    try:
        redis_connection().ping()
    except RedisError as exc:
        raise QueueUnavailable("Redis queue unavailable") from exc


def create_job(db: Session, project_id: str, kind: str, payload: dict[str, Any]) -> BackgroundJob:
    row = BackgroundJob(
        id=new_id("job"),
        project_id=project_id,
        kind=kind,
        payload=redact_value(payload),
    )
    db.add(row)
    db.add(
        OutboxEvent(
            id=f"outbox_{row.id}",
            project_id=project_id,
            topic="background_job.created",
            payload={"job_id": row.id, "queue_name": "default"},
            status="pending",
            available_at=datetime.now(UTC),
        )
    )
    db.flush()
    return row


def dispatch_outbox_batch(
    db: Session,
    *,
    dispatcher_id: str,
    limit: int = 50,
) -> int:
    now = datetime.now(UTC)
    candidates = (
        db.query(OutboxEvent.id)
        .filter(
            OutboxEvent.available_at <= now,
            (OutboxEvent.status == "pending")
            | ((OutboxEvent.status == "dispatching") & (OutboxEvent.lease_expires_at < now)),
        )
        .order_by(OutboxEvent.available_at.asc(), OutboxEvent.created_at.asc())
        .limit(limit)
        .all()
    )
    delivered = 0
    for (event_id,) in candidates:
        lease_until = datetime.now(UTC) + timedelta(seconds=30)
        claimed = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.id == event_id,
                (OutboxEvent.status == "pending")
                | (
                    (OutboxEvent.status == "dispatching")
                    & (OutboxEvent.lease_expires_at < datetime.now(UTC))
                ),
            )
            .update(
                {
                    OutboxEvent.status: "dispatching",
                    OutboxEvent.lease_owner: dispatcher_id,
                    OutboxEvent.lease_expires_at: lease_until,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if claimed != 1:
            continue
        event = db.get(OutboxEvent, event_id)
        assert event is not None
        job_id = str(event.payload["job_id"])
        queue_name = str(event.payload["queue_name"])
        job = db.get(BackgroundJob, job_id)
        if job is None:
            event.status = "dead"
            event.last_error_code = "job_not_found"
            db.commit()
            continue
        try:
            queue = Queue(queue_name, connection=redis_connection())
            rq_job = queue.fetch_job(event.id)
            if rq_job is None:
                rq_job = queue.enqueue(
                    "agentops_guard.backend.services.jobs.execute_job",
                    job_id,
                    job_id=event.id,
                    job_timeout=600,
                )
        except DuplicateJobError:
            try:
                rq_job = RqJob.fetch(event.id, connection=redis_connection())
            except RedisError:
                _release_outbox_after_redis_failure(db, event)
                continue
        except RedisError:
            _release_outbox_after_redis_failure(db, event)
            continue
        job.rq_job_id = rq_job.id
        event.status = "delivered"
        event.attempts += 1
        event.delivered_at = datetime.now(UTC)
        event.lease_owner = None
        event.lease_expires_at = None
        event.last_error_code = None
        db.commit()
        delivered += 1
    return delivered


def enqueue_job(db: Session, row: BackgroundJob, queue_name: str = "default") -> BackgroundJob:
    assert_redis_available()
    queue = Queue(queue_name, connection=redis_connection())
    rq_job = queue.enqueue(
        "agentops_guard.backend.services.jobs.execute_job", row.id, job_timeout=600
    )
    row.rq_job_id = rq_job.id
    db.flush()
    return row


def execute_job(job_id: str) -> dict[str, Any]:
    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, job_id)
        if row is None:
            raise ValueError(f"Job not found: {job_id}")
        if row.status == "completed":
            return row.result or {}
        current_rq_job = get_current_job()
        claimant = current_rq_job.id if current_rq_job is not None else "direct-executor"
        claimed = claim_background_job(db, job_id=job_id, claimant=claimant)
        db.commit()
        if not claimed:
            db.expire_all()
            row = db.get(BackgroundJob, job_id)
            if row is not None and row.status == "completed":
                return row.result or {}
            raise JobAlreadyClaimed(f"Job cannot be claimed from status: {row.status}")
        db.expire_all()
        row = db.get(BackgroundJob, job_id)
        assert row is not None
        stop_heartbeat, lease_lost, heartbeat = _start_job_heartbeat(job_id, claimant)
        completed = False
        failure_code = "job_execution_failed"
        try:
            result = _execute_payload(db, row)
            stop_heartbeat.set()
            heartbeat.join(timeout=5)
            if heartbeat.is_alive() or lease_lost.is_set():
                failure_code = "worker_lease_lost"
                raise JobLeaseLost("Background job lease was lost")
            row.status = "completed"
            row.result = result
            row.error = None
            row.lease_owner = None
            row.lease_expires_at = None
            row.finished_at = datetime.now(UTC)
            db.commit()
            completed = True
            return result
        finally:
            stop_heartbeat.set()
            heartbeat.join(timeout=5)
            if not completed:
                db.rollback()
                row = db.get(BackgroundJob, job_id)
                if row is not None and row.status == "running" and row.lease_owner == claimant:
                    _mark_job_for_retry_or_dead(db, row, failure_code)
                    db.commit()
    finally:
        db.close()


def claim_background_job(db: Session, *, job_id: str, claimant: str) -> bool:
    now = datetime.now(UTC)
    claimed = (
        db.query(BackgroundJob)
        .filter(
            BackgroundJob.id == job_id,
            BackgroundJob.status == "pending",
        )
        .update(
            {
                BackgroundJob.status: "running",
                BackgroundJob.attempts: BackgroundJob.attempts + 1,
                BackgroundJob.started_at: now,
                BackgroundJob.lease_owner: claimant,
                BackgroundJob.lease_expires_at: now + timedelta(seconds=JOB_LEASE_SECONDS),
            },
            synchronize_session=False,
        )
    )
    return claimed == 1


def renew_background_job_lease(db: Session, *, job_id: str, claimant: str) -> bool:
    now = datetime.now(UTC)
    renewed = (
        db.query(BackgroundJob)
        .filter(
            BackgroundJob.id == job_id,
            BackgroundJob.status == "running",
            BackgroundJob.lease_owner == claimant,
            BackgroundJob.lease_expires_at >= now,
        )
        .update(
            {
                BackgroundJob.lease_expires_at: now
                + timedelta(seconds=JOB_LEASE_SECONDS),
            },
            synchronize_session=False,
        )
    )
    return renewed == 1


def _start_job_heartbeat(job_id: str, claimant: str) -> tuple[Event, Event, Thread]:
    stop = Event()
    lease_lost = Event()

    def heartbeat_loop() -> None:
        while not stop.wait(JOB_HEARTBEAT_SECONDS):
            heartbeat_db = SessionLocal()
            try:
                if not renew_background_job_lease(
                    heartbeat_db,
                    job_id=job_id,
                    claimant=claimant,
                ):
                    JOB_HEARTBEAT_FAILURES_COUNTER.labels(reason="lease_lost").inc()
                    lease_lost.set()
                    return
                heartbeat_db.commit()
            except SQLAlchemyError:
                heartbeat_db.rollback()
                JOB_HEARTBEAT_FAILURES_COUNTER.labels(reason="database_error").inc()
                lease_lost.set()
                return
            finally:
                heartbeat_db.close()

    thread = Thread(target=heartbeat_loop, name="agentops-job-heartbeat", daemon=True)
    thread.start()
    return stop, lease_lost, thread


def reconcile_background_job_leases(db: Session) -> int:
    now = datetime.now(UTC)
    rows = (
        db.query(BackgroundJob)
        .filter(
            BackgroundJob.status == "running",
            BackgroundJob.lease_expires_at < now,
        )
        .with_for_update(skip_locked=True)
        .all()
    )
    for row in rows:
        _mark_job_for_retry_or_dead(db, row, "worker_lease_expired")
        JOB_LEASE_RECOVERIES_COUNTER.labels(outcome=row.status).inc()
    db.flush()
    return len(rows)


def background_job_reconciliation(
    db: Session,
    *,
    project_id: str,
    stale_after_seconds: int = 300,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    stale_before = now - timedelta(seconds=stale_after_seconds)
    return {
        "project_id": project_id,
        "stale_pending_jobs": db.query(BackgroundJob)
        .filter(
            BackgroundJob.project_id == project_id,
            BackgroundJob.status == "pending",
            BackgroundJob.created_at < stale_before,
        )
        .count(),
        "expired_running_jobs": db.query(BackgroundJob)
        .filter(
            BackgroundJob.project_id == project_id,
            BackgroundJob.status == "running",
            BackgroundJob.lease_expires_at < now,
        )
        .count(),
        "dead_jobs": db.query(BackgroundJob)
        .filter(
            BackgroundJob.project_id == project_id,
            BackgroundJob.status == "dead",
        )
        .count(),
        "undelivered_outbox_events": db.query(OutboxEvent)
        .filter(
            OutboxEvent.project_id == project_id,
            OutboxEvent.status.in_(["pending", "dispatching"]),
        )
        .count(),
        "outcome_unknown_executions": db.query(ExecutionRequest)
        .filter(
            ExecutionRequest.project_id == project_id,
            ExecutionRequest.status == "outcome_unknown",
        )
        .count(),
        "checked_at": now,
    }


def retry_dead_job(db: Session, row: BackgroundJob) -> BackgroundJob:
    if row.status != "dead" or row.kind not in RETRYABLE_JOB_KINDS:
        raise ValueError("Background job is not eligible for retry")
    retried = create_job(db, row.project_id, row.kind, row.payload or {})
    record_audit(
        db,
        project_id=row.project_id,
        action="background_job.retry",
        resource_type="background_job",
        resource_id=retried.id,
        metadata={"retry_of": row.id},
    )
    db.flush()
    return retried


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
    except (NoSuchJobError, RedisError):
        return None


def _mark_job_for_retry_or_dead(
    db: Session,
    row: BackgroundJob,
    error_code: str,
) -> None:
    row.lease_owner = None
    row.lease_expires_at = None
    row.result = None
    row.error = error_code
    if row.attempts >= MAX_JOB_ATTEMPTS:
        row.status = "dead"
        row.finished_at = datetime.now(UTC)
        return
    row.status = "pending"
    row.finished_at = None
    event_id = f"outbox_retry_{row.id}_{row.attempts}"
    if db.get(OutboxEvent, event_id) is None:
        db.add(
            OutboxEvent(
                id=event_id,
                project_id=row.project_id,
                topic="background_job.retry",
                payload={"job_id": row.id, "queue_name": "default"},
                status="pending",
                available_at=datetime.now(UTC) + timedelta(seconds=5 * row.attempts),
            )
        )


def _release_outbox_after_redis_failure(db: Session, event: OutboxEvent) -> None:
    event.status = "pending"
    event.attempts += 1
    event.available_at = datetime.now(UTC) + timedelta(seconds=5)
    event.lease_owner = None
    event.lease_expires_at = None
    event.last_error_code = "redis_unavailable"
    db.commit()
