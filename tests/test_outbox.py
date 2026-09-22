from datetime import UTC, datetime, timedelta
import time
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from redis.exceptions import RedisError

from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.main import app
from agentops_guard.backend.models import BackgroundJob, OutboxEvent
from agentops_guard.backend.services import jobs


client = TestClient(app)
headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_job_and_outbox_roll_back_together():
    db = SessionLocal()
    job_id = None
    try:
        row = jobs.create_job(db, "default", "unknown", {})
        job_id = row.id
        db.rollback()
    finally:
        db.close()

    db = SessionLocal()
    try:
        assert db.get(BackgroundJob, job_id) is None
        assert db.get(OutboxEvent, f"outbox_{job_id}") is None
    finally:
        db.close()


def test_dispatcher_retries_redis_failure_and_delivers_same_event_id(monkeypatch):
    project_id = f"outbox_{uuid4().hex}"
    db = SessionLocal()
    try:
        db.query(OutboxEvent).filter(OutboxEvent.project_id.like("outbox_%")).delete()
        db.query(BackgroundJob).filter(BackgroundJob.project_id.like("outbox_%")).delete()
        row = jobs.create_job(db, project_id, "unknown", {})
        job_id = row.id
        event = db.get(OutboxEvent, f"outbox_{job_id}")
        assert event is not None
        event.available_at = datetime(2000, 1, 1, tzinfo=UTC)
        db.commit()
    finally:
        db.close()

    class DownQueue:
        def __init__(self, *_args, **_kwargs):
            pass

        def fetch_job(self, _job_id):
            return None

        def enqueue(self, *_args, **_kwargs):
            raise RedisError("down")

    monkeypatch.setattr(jobs, "Queue", DownQueue)
    db = SessionLocal()
    try:
        assert jobs.dispatch_outbox_batch(db, dispatcher_id="test-down", limit=1) == 0
    finally:
        db.close()

    db = SessionLocal()
    try:
        event = db.get(OutboxEvent, f"outbox_{job_id}")
        assert event is not None
        assert event.status == "pending"
        assert event.last_error_code == "redis_unavailable"
        assert db.get(BackgroundJob, job_id) is not None
        event.available_at = datetime(2000, 1, 1, tzinfo=UTC)
        db.commit()
    finally:
        db.close()

    enqueued_ids: list[str] = []
    existing_jobs: dict[str, SimpleNamespace] = {}

    class HealthyQueue:
        def __init__(self, *_args, **_kwargs):
            pass

        def fetch_job(self, job_id):
            return existing_jobs.get(job_id)

        def enqueue(self, *_args, **kwargs):
            enqueued_ids.append(kwargs["job_id"])
            queued = SimpleNamespace(id=kwargs["job_id"])
            existing_jobs[queued.id] = queued
            return queued

    monkeypatch.setattr(jobs, "Queue", HealthyQueue)
    monkeypatch.setattr(jobs, "redis_connection", lambda: object())
    db = SessionLocal()
    try:
        assert jobs.dispatch_outbox_batch(db, dispatcher_id="test-up", limit=1) == 1
    finally:
        db.close()

    db = SessionLocal()
    try:
        event = db.get(OutboxEvent, f"outbox_{job_id}")
        row = db.get(BackgroundJob, job_id)
        assert event is not None
        assert row is not None
        assert event.status == "delivered"
        assert row.rq_job_id == event.id
        assert enqueued_ids == [event.id]
        event.status = "pending"
        event.available_at = datetime(2000, 1, 1, tzinfo=UTC)
        event.delivered_at = None
        db.commit()
        assert jobs.dispatch_outbox_batch(db, dispatcher_id="test-repeat", limit=1) == 1
        assert enqueued_ids == [event.id]
        db.delete(event)
        db.delete(row)
        db.commit()
    finally:
        db.close()


def test_running_job_cannot_be_claimed_twice():
    project_id = f"job_claim_{uuid4().hex}"
    db = SessionLocal()
    try:
        row = jobs.create_job(db, project_id, "unknown", {})
        row.status = "running"
        row.attempts = 1
        row.lease_owner = "first-worker"
        row.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
        db.commit()
        job_id = row.id
    finally:
        db.close()

    try:
        jobs.execute_job(job_id)
    except jobs.JobAlreadyClaimed:
        pass
    else:
        raise AssertionError("a running job must not be claimed twice")

    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, job_id)
        assert row is not None
        assert row.status == "running"
        assert row.attempts == 1
        assert row.lease_owner == "first-worker"
        db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete()
        db.delete(row)
        db.commit()
    finally:
        db.close()


def test_expired_job_lease_is_requeued_then_dead_after_attempt_limit():
    project_id = f"job_lease_{uuid4().hex}"
    db = SessionLocal()
    try:
        row = jobs.create_job(db, project_id, "unknown", {})
        row.status = "running"
        row.attempts = 1
        row.lease_owner = "lost-worker"
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()

        assert jobs.reconcile_background_job_leases(db) >= 1
        db.commit()
        assert row.status == "pending"
        assert row.error == "worker_lease_expired"
        assert db.get(OutboxEvent, f"outbox_retry_{row.id}_1") is not None

        row.status = "running"
        row.attempts = jobs.MAX_JOB_ATTEMPTS
        row.lease_owner = "lost-worker"
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()

        assert jobs.reconcile_background_job_leases(db) >= 1
        db.commit()
        assert row.status == "dead"
        assert row.finished_at is not None
        db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete()
        db.delete(row)
        db.commit()
    finally:
        db.close()


def test_active_worker_can_renew_only_its_unexpired_lease():
    project_id = f"job_heartbeat_{uuid4().hex}"
    db = SessionLocal()
    try:
        row = jobs.create_job(db, project_id, "unknown", {})
        db.commit()
        assert jobs.claim_background_job(db, job_id=row.id, claimant="worker-one") is True
        db.commit()
        db.refresh(row)
        original_expiry = row.lease_expires_at

        assert (
            jobs.renew_background_job_lease(
                db,
                job_id=row.id,
                claimant="worker-two",
            )
            is False
        )
        assert (
            jobs.renew_background_job_lease(
                db,
                job_id=row.id,
                claimant="worker-one",
            )
            is True
        )
        db.commit()
        db.refresh(row)
        assert row.lease_expires_at > original_expiry

        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        assert (
            jobs.renew_background_job_lease(
                db,
                job_id=row.id,
                claimant="worker-one",
            )
            is False
        )
        db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete()
        db.delete(row)
        db.commit()
    finally:
        db.close()


def test_worker_stops_without_committing_when_heartbeat_loses_lease(monkeypatch):
    project_id = f"job_lost_lease_{uuid4().hex}"
    db = SessionLocal()
    try:
        row = jobs.create_job(db, project_id, "unknown", {})
        db.commit()
        job_id = row.id
    finally:
        db.close()

    monkeypatch.setattr(jobs, "JOB_HEARTBEAT_SECONDS", 0.001)
    monkeypatch.setattr(jobs, "renew_background_job_lease", lambda *_args, **_kwargs: False)

    def slow_payload(_db, _row, *, claimant):
        time.sleep(0.02)
        return {"should_not_commit": True}

    monkeypatch.setattr(jobs, "_execute_payload", slow_payload)

    with pytest.raises(jobs.JobLeaseLost):
        jobs.execute_job(job_id)

    db = SessionLocal()
    try:
        row = db.get(BackgroundJob, job_id)
        assert row is not None
        assert row.status == "pending"
        assert row.result is None
        assert row.error == "worker_lease_lost"
        assert db.get(OutboxEvent, f"outbox_retry_{row.id}_1") is not None
        db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete()
        db.delete(row)
        db.commit()
    finally:
        db.close()


def test_dead_job_filter_and_payload_redaction():
    project_id = f"job_failures_{uuid4().hex}"
    canary = "sk-abcdefghijklmnopqrstuvwxyz123456"
    db = SessionLocal()
    try:
        dead = jobs.create_job(db, project_id, "eval_run", {"token": canary})
        dead.status = "dead"
        dead.error = "job_execution_failed"
        pending = jobs.create_job(db, project_id, "replay", {})
        db.commit()
        dead_id = dead.id
        pending_id = pending.id
    finally:
        db.close()

    response = client.get(
        "/v1/jobs",
        headers=headers,
        params={"project_id": project_id, "status": "dead"},
    )
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [dead_id]
    assert canary not in response.text

    report = client.get(
        "/v1/jobs/reconciliation",
        headers=headers,
        params={"project_id": project_id},
    )
    assert report.status_code == 200
    assert report.json()["dead_jobs"] == 1
    assert report.json()["undelivered_outbox_events"] == 2

    not_retryable = client.post(f"/v1/jobs/{pending_id}/retry", headers=headers)
    assert not_retryable.status_code == 409
    retried = client.post(f"/v1/jobs/{dead_id}/retry", headers=headers)
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"
    assert retried.json()["id"] not in {dead_id, pending_id}
    assert canary not in retried.text

    db = SessionLocal()
    try:
        db.query(OutboxEvent).filter(OutboxEvent.project_id == project_id).delete()
        db.query(BackgroundJob).filter(BackgroundJob.project_id == project_id).delete()
        db.commit()
    finally:
        db.close()
