from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from redis.exceptions import RedisError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from test_tool_invocations import setup_invocation as setup_invocation, review, enqueue, status
from test_database_resilience import postgres_url as postgres_url
from agentops_guard.backend.database import Base, SessionLocal
from agentops_guard.backend.config import Settings
from agentops_guard.backend.database_resilience import create_database_engine
from agentops_guard.backend.models import BackgroundJob, OutboxEvent, ToolInvocation
from agentops_guard.backend.services import jobs, tool_invocations as receipts


def test_expired_queue_preparation_is_recovering_not_terminal(setup_invocation):
    project, server, *_ = setup_invocation
    review(project, server)
    invocation_id, _ = enqueue(setup_invocation)
    with SessionLocal() as db:
        row = db.get(ToolInvocation, invocation_id)
        row.status = "preparing"
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    assert status(setup_invocation)["state"] == "recovering"


def test_takeover_fences_old_dispatch_claim_and_result(setup_invocation):
    project, server, _, _, calls = setup_invocation
    review(project, server)
    invocation_id, job_id = enqueue(setup_invocation)
    with SessionLocal() as db:
        assert jobs.claim_background_job(db, job_id=job_id, claimant="old-worker")
        db.commit()
        job = db.get(BackgroundJob, job_id)
        assert (receipts._utc(job.lease_expires_at) - datetime.now(UTC)).total_seconds() <= jobs.TOOL_JOB_LEASE_SECONDS
        row = db.get(ToolInvocation, invocation_id)
        row.status, row.lease_token = "preparing", str(uuid4())
        row.lease_expires_at = datetime.now(UTC) + timedelta(seconds=120)
        old = receipts.InvocationAttempt(row, row.lease_token, (job_id, "old-worker"))
        job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        jobs.reconcile_background_job_leases(db)
        db.commit()
        db.refresh(row)
        assert row.status == "queued" and row.lease_token is None and row.attempts == 0
        assert db.get(OutboxEvent, f"outbox_retry_{job_id}_1") is not None
        with pytest.raises(jobs.JobLeaseLost):
            old.dispatch(db, row.revision_digest)
        db.rollback()
        # Even if its ORM job object is refreshed to the new owner, an old
        # worker must not borrow that owner's identity.
        assert jobs.claim_background_job(db, job_id=job_id, claimant="new-worker")
        db.commit()
        db.refresh(job)
        with pytest.raises(jobs.JobLeaseLost):
            receipts.execute_queued(db, job, claimant="old-worker")
        db.rollback()
        job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        jobs.reconcile_background_job_leases(db)
        db.commit()
    assert jobs.execute_job(job_id)["state"] == "succeeded"
    assert len(calls) == 1
    with SessionLocal() as db:
        with pytest.raises(jobs.JobLeaseLost):
            receipts._finish(db, old, "failed", {"code": "stale-worker"})
        db.rollback()
        assert db.get(ToolInvocation, invocation_id).status == "succeeded"


def test_lost_dispatched_worker_is_settled_without_replay(setup_invocation):
    project, server, _, _, calls = setup_invocation
    review(project, server, retry="read_only")
    invocation_id, job_id = enqueue(setup_invocation)
    with SessionLocal() as db:
        jobs.claim_background_job(db, job_id=job_id, claimant="lost-worker")
        db.commit()
        row = db.get(ToolInvocation, invocation_id)
        row.status, row.attempts, row.lease_token = "dispatched", 1, str(uuid4())
        row.lease_expires_at = datetime.now(UTC) + timedelta(seconds=120)
        db.get(BackgroundJob, job_id).lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        jobs.reconcile_background_job_leases(db)
        db.commit()
        db.refresh(row)
        assert row.status == "outcome_unknown" and row.encrypted_payload is None
        assert db.get(BackgroundJob, job_id).status == "completed"
        assert db.get(OutboxEvent, f"outbox_retry_{job_id}_1") is None
    assert jobs.execute_job(job_id)["state"] == "outcome_unknown"
    assert not calls


def test_old_delivery_recovery_does_not_change_resumed_approval(setup_invocation):
    project, server, *_ = setup_invocation
    review(project, server)
    invocation_id, old_job_id = enqueue(setup_invocation)
    with SessionLocal() as db:
        assert jobs.claim_background_job(db, job_id=old_job_id, claimant="lost-worker")
        db.commit()
        row = db.get(ToolInvocation, invocation_id)
        row.status = "waiting_approval"
        db.commit()
        receipts.resume(db, row)
        resumed_job_id = row.job_id
        assert resumed_job_id != old_job_id
        db.get(BackgroundJob, old_job_id).lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        jobs.reconcile_background_job_leases(db)
        db.commit()
        db.refresh(row)
        assert row.status == "queued" and row.job_id == resumed_job_id and row.encrypted_payload
        assert db.get(BackgroundJob, resumed_job_id).status == "pending"
        old_job = db.get(BackgroundJob, old_job_id)
        assert old_job.status == "completed" and old_job.result["superseded"] is True
        assert db.get(OutboxEvent, f"outbox_retry_{old_job_id}_1") is None


@pytest.fixture
def delivery_db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)() as db:
        yield db
    engine.dispose()


def delivered_job(db):
    job = jobs.create_job(db, "delivery-recovery", "tool_invocation", {"invocation_id": "inv_" + uuid4().hex[:24]})
    job.created_at = datetime.now(UTC) - timedelta(seconds=90)
    event = db.get(OutboxEvent, "outbox_" + job.id)
    event.status = "delivered"
    event.delivered_at = datetime.now(UTC) - timedelta(seconds=60)
    event.payload = {"job_id": job.id, "queue_name": "isolated-test-queue"}
    job.rq_job_id = event.id
    db.commit()
    return job


@pytest.mark.parametrize("present,member,expected", [(False, False, 1), (True, False, 1), (True, True, 0)])
def test_lost_notification_is_recreated_without_new_tool_attempt(delivery_db, monkeypatch, present, member, expected):
    db = delivery_db
    job = delivered_job(db)
    connection = SimpleNamespace(lpos=lambda *a: 0 if member else None)
    monkeypatch.setattr(jobs, "redis_connection", lambda **kw: connection)
    rq_job = SimpleNamespace(id=job.rq_job_id, get_status=lambda **kw: SimpleNamespace(value="queued"))
    monkeypatch.setattr(jobs, "Queue", lambda *a, **kw: SimpleNamespace(
        key="rq:queue:isolated-test-queue", fetch_job=lambda id: rq_job if present else None))
    assert jobs.reconcile_missing_tool_deliveries(db)[0] == expected
    db.commit()
    assert job.attempts == 0 and job.status == "pending"
    assert jobs.reconcile_missing_tool_deliveries(db)[0] == 0
    events = db.query(OutboxEvent).filter_by(status="pending").all()
    assert len(events) == expected
    if events:
        assert events[0].payload == {"job_id": job.id, "queue_name": "isolated-test-queue"}


def test_redis_unreachable_is_not_treated_as_missing(delivery_db, monkeypatch):
    db = delivery_db
    delivered_job(db)
    monkeypatch.setattr(jobs, "redis_connection", lambda **kw: object())
    def fail(*a):
        raise RedisError("unavailable")
    monkeypatch.setattr(jobs, "Queue", lambda *a, **kw: SimpleNamespace(fetch_job=fail))
    assert jobs.reconcile_missing_tool_deliveries(db)[0] == 0
    assert db.query(OutboxEvent).filter_by(status="pending").count() == 0


@pytest.mark.parametrize("started_age,expected", [(1, 0), (90, 1)])
def test_delivery_repair_allows_recent_rq_start_to_claim_database(delivery_db, monkeypatch, started_age, expected):
    db = delivery_db
    job = delivered_job(db)
    monkeypatch.setattr(jobs, "redis_connection", lambda **kw: object())
    rq_job = SimpleNamespace(
        id=job.rq_job_id,
        started_at=datetime.now(UTC) - timedelta(seconds=started_age),
        get_status=lambda **kw: SimpleNamespace(value="started"),
    )
    monkeypatch.setattr(jobs, "Queue", lambda *a, **kw: SimpleNamespace(fetch_job=lambda id: rq_job))
    assert jobs.reconcile_missing_tool_deliveries(db)[0] == expected
    assert job.status == "pending" and job.attempts == 0


def test_delivery_scan_cursor_moves_past_healthy_old_backlog(delivery_db, monkeypatch):
    db = delivery_db
    rows = sorted([delivered_job(db) for _ in range(3)], key=lambda row: row.id)
    monkeypatch.setattr(jobs, "redis_connection", lambda **kw: SimpleNamespace(lpos=lambda *a: 0))
    monkeypatch.setattr(jobs, "Queue", lambda *a, **kw: SimpleNamespace(
        key="queue", fetch_job=lambda id: None if id == rows[-1].rq_job_id else SimpleNamespace(
            id=id, get_status=lambda **kw: SimpleNamespace(value="queued"))))
    repaired, cursor = jobs.reconcile_missing_tool_deliveries(db, limit=2)
    assert repaired == 0 and cursor == rows[1].id
    repaired, cursor = jobs.reconcile_missing_tool_deliveries(db, limit=2, after_id=cursor)
    assert repaired == 1 and cursor is None


def test_late_job_completion_cannot_overwrite_replacement_owner(monkeypatch):
    with SessionLocal() as db:
        row = jobs.create_job(db, "late-completion-" + uuid4().hex, "unknown", {})
        db.commit()
        job_id = row.id
    def pause_and_take_over(db, row, *, claimant):
        db.rollback()
        with SessionLocal() as replacement:
            current = replacement.get(BackgroundJob, job_id)
            current.lease_owner = "replacement-worker"
            replacement.commit()
        return {"stale": True}
    monkeypatch.setattr(jobs, "_execute_payload", pause_and_take_over)
    with pytest.raises(jobs.JobLeaseLost):
        jobs.execute_job(job_id)
    with SessionLocal() as db:
        row = db.get(BackgroundJob, job_id)
        assert row.status == "running" and row.lease_owner == "replacement-worker"
        assert row.result is None
        # Remove only the synthetic lease, which has no actual replacement worker.
        db.query(OutboxEvent).filter_by(project_id=row.project_id).delete()
        db.delete(row)
        db.commit()


def test_postgres_concurrent_recovery_has_one_replacement_and_fences_old_worker(postgres_url, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    engine = create_database_engine(Settings(database_url=postgres_url.render_as_string(hide_password=False)), pool_size=4)
    try:
        Base.metadata.create_all(engine)
        sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        with sessions() as db:
            row = ToolInvocation(id="inv_" + uuid4().hex[:24], project_id="pg-fencing",
                request_id=str(uuid4()), actor_digest="a" * 64, payload_digest="b" * 64,
                tool_id="controlled:read", revision_digest="c" * 64,
                mode="queued", status="preparing", attempts=0, lease_token=str(uuid4()),
                lease_expires_at=datetime.now(UTC) + timedelta(seconds=120),
                expires_at=datetime.now(UTC) + timedelta(hours=1), encrypted_payload="test-envelope")
            db.add(row)
            job = jobs.create_job(db, row.project_id, "tool_invocation", {"invocation_id": row.id})
            row.job_id = job.id
            db.commit()
            assert jobs.claim_background_job(db, job_id=job.id, claimant="old-worker")
            db.commit()
            db.refresh(job)
            job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()
            old = receipts.InvocationAttempt(row, row.lease_token, (job.id, "old-worker"))
            job_id, invocation_id = job.id, row.id
        barrier = Barrier(2)
        def recover():
            with sessions() as db:
                barrier.wait(timeout=10)
                count = jobs.reconcile_background_job_leases(db)
                db.commit()
                return count
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(recover) for _ in range(2)]
            assert sum(f.result(timeout=15) for f in futures) == 1
        monkeypatch.setattr(receipts, "queued_identity", lambda *a: None)
        monkeypatch.setattr(receipts, "_reviewed_policy", lambda *a: None)
        with sessions() as db:
            assert db.query(OutboxEvent).filter_by(topic="background_job.retry").count() == 1
            with pytest.raises(jobs.JobLeaseLost):
                old.dispatch(db, "c" * 64)
            db.rollback()
            assert jobs.claim_background_job(db, job_id=job_id, claimant="new-worker")
            row = db.get(ToolInvocation, invocation_id)
            row.status, row.lease_token = "preparing", str(uuid4())
            row.lease_expires_at = datetime.now(UTC) + timedelta(seconds=120)
            db.commit()
            new = receipts.InvocationAttempt(row, row.lease_token, (job_id, "new-worker"))
            new.dispatch(db, "c" * 64)
            db.refresh(row)
            assert row.attempts == 1 and row.status == "dispatched"
            with pytest.raises(jobs.JobLeaseLost):
                old.dispatch(db, "c" * 64)
            db.rollback()
    finally:
        engine.dispose()
