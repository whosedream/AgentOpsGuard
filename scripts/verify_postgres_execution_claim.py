from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.models import BackgroundJob, ExecutionRequest
from agentops_guard.backend.services.execution_requests import match_and_claim_execution
from agentops_guard.backend.services.jobs import claim_background_job, renew_background_job_lease
from agentops_guard.backend.services.mcp_tool_revisions import content_digest


def main() -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("This verification requires PostgreSQL")
    suffix = uuid4().hex
    project_id = f"claim_project_{suffix}"
    subject = {"agent_id": "claim-test-agent"}
    arguments = {"record_id": "claim-test-record"}
    policy_snapshot = {"builtin_policy_version": "claim-test"}
    tool_revision_id = f"toolrev_{suffix}"
    tool_revision_digest = content_digest({"revision": suffix})
    row = ExecutionRequest(
        id=f"exec_{suffix}",
        project_id=project_id,
        decision_id=f"policy_{suffix}",
        approval_id=f"approval_{suffix}",
        subject=subject,
        actor_digest=content_digest(subject),
        server_id=f"server_{suffix}",
        tool_name="records.update",
        tool_revision_id=tool_revision_id,
        tool_revision_digest=tool_revision_digest,
        arguments_digest=content_digest(arguments),
        policy_snapshot=policy_snapshot,
        policy_snapshot_digest=content_digest(policy_snapshot),
        risk_labels=[],
        status="approved",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    db = SessionLocal()
    try:
        db.add(row)
        db.commit()
        execution_id = row.id
    finally:
        db.close()

    def claim(worker: int) -> str:
        session = SessionLocal()
        try:
            result = match_and_claim_execution(
                session,
                project_id=project_id,
                run_id=None,
                subject=subject,
                server_id=f"server_{suffix}",
                tool_name="records.update",
                tool_revision_id=tool_revision_id,
                tool_revision_digest=tool_revision_digest,
                arguments=arguments,
                policy_snapshot=policy_snapshot,
                claimant=f"worker-{worker}",
                idempotency_key=None,
            )
            session.commit()
            return result.kind
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(claim, range(10)))
    claimed = outcomes.count("claimed")
    if claimed != 1:
        raise RuntimeError(f"expected one claim, got {claimed}")

    db = SessionLocal()
    try:
        stored = db.get(ExecutionRequest, execution_id)
        assert stored is not None
        final_status = stored.status
        db.delete(stored)
        db.commit()
    finally:
        db.close()

    background_job_id = f"job_{suffix[:24]}"
    db = SessionLocal()
    try:
        db.add(
            BackgroundJob(
                id=background_job_id,
                project_id=project_id,
                kind="claim-test",
                status="pending",
                payload={},
            )
        )
        db.commit()
    finally:
        db.close()

    def claim_job(worker: int) -> tuple[int, bool]:
        session = SessionLocal()
        try:
            claimed_job = claim_background_job(
                session,
                job_id=background_job_id,
                claimant=f"worker-{worker}",
            )
            session.commit()
            return worker, claimed_job
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=10) as pool:
        job_outcomes = list(pool.map(claim_job, range(10)))
    background_job_claimed = sum(claimed_job for _, claimed_job in job_outcomes)
    if background_job_claimed != 1:
        raise RuntimeError(f"expected one background job claim, got {background_job_claimed}")
    winning_worker = next(worker for worker, claimed_job in job_outcomes if claimed_job)

    db = SessionLocal()
    try:
        contender_renewed = renew_background_job_lease(
            db,
            job_id=background_job_id,
            claimant="worker-not-owner",
        )
        owner_renewed = renew_background_job_lease(
            db,
            job_id=background_job_id,
            claimant=f"worker-{winning_worker}",
        )
        db.commit()
    finally:
        db.close()
    if contender_renewed or not owner_renewed:
        raise RuntimeError("background job lease ownership was not enforced")

    db = SessionLocal()
    try:
        stored_job = db.get(BackgroundJob, background_job_id)
        assert stored_job is not None
        background_job_status = stored_job.status
        db.delete(stored_job)
        db.commit()
    finally:
        db.close()
    print(
        json.dumps(
            {
                "workers": 10,
                "claimed": claimed,
                "rejected": 9,
                "final_status": final_status,
                "background_job_claimed": background_job_claimed,
                "background_job_rejected": 9,
                "background_job_status": background_job_status,
                "heartbeat_owner_renewed": owner_renewed,
                "heartbeat_contender_renewed": contender_renewed,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
