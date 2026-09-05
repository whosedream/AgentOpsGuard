from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from agentops_guard.backend.database import SessionLocal, init_db
from agentops_guard.backend.main import app
from agentops_guard.backend.models import AuditLog, ExecutionRequest
from agentops_guard.backend.services.execution_requests import (
    ExecutionClaimConflict,
    OutcomeResolutionConflict,
    mark_execution_result,
    match_and_claim_execution,
    reconcile_execution_leases,
    release_execution_claim,
    resolve_unknown_outcome,
)
from agentops_guard.backend.services.mcp_tool_revisions import content_digest
from agentops_guard.backend.services.api_keys import create_api_key
from agentops_guard.backend.services.projects import ensure_project


client = TestClient(app)
operator_headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}
init_db()


def _execution(status: str, lease_expires_at=None) -> ExecutionRequest:
    suffix = uuid4().hex
    return ExecutionRequest(
        id=f"exec_{suffix}",
        project_id=f"project_{suffix}",
        decision_id=f"policy_{suffix}",
        approval_id=f"approval_{suffix}",
        subject={"agent_id": "test-agent"},
        actor_digest="a" * 64,
        server_id=f"server_{suffix}",
        tool_name="demo.echo",
        tool_revision_id=f"toolrev_{suffix}",
        tool_revision_digest="b" * 64,
        arguments_digest="c" * 64,
        policy_snapshot={},
        policy_snapshot_digest="d" * 64,
        status=status,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        lease_expires_at=lease_expires_at,
    )


def test_expired_execution_lease_becomes_outcome_unknown_without_retry():
    db = SessionLocal()
    try:
        row = _execution(
            "execution_claimed",
            datetime.now(UTC) - timedelta(seconds=1),
        )
        db.add(row)
        db.commit()
        assert reconcile_execution_leases(db) >= 1
        db.commit()
        db.refresh(row)
        assert row.status == "outcome_unknown"
        assert row.result_summary["reason"] == "execution_lease_expired"
        assert reconcile_execution_leases(db) == 0
    finally:
        db.close()


def test_only_claimed_execution_can_record_a_result():
    db = SessionLocal()
    try:
        row = _execution("approved")
        db.add(row)
        db.flush()
        with pytest.raises(ValueError, match="not claimed"):
            mark_execution_result(db, row, {"content": []})
    finally:
        db.rollback()
        db.close()


@pytest.mark.parametrize(
    ("resolution", "expected_status", "expected_outcome"),
    [
        ("confirmed_succeeded", "succeeded", "succeeded"),
        ("confirmed_failed", "failed", "failed"),
    ],
)
def test_operator_can_close_unknown_outcome_with_digest_only(
    resolution,
    expected_status,
    expected_outcome,
):
    db = SessionLocal()
    try:
        row = _execution("outcome_unknown")
        db.add(row)
        db.commit()
        execution_id = row.id
        project_id = row.project_id
    finally:
        db.close()

    evidence_sha256 = "e" * 64
    response = client.post(
        f"/v1/executions/{execution_id}/resolve",
        headers=operator_headers,
        json={"resolution": resolution, "evidence_sha256": evidence_sha256},
    )
    assert response.status_code == 200
    assert response.json() == {
        "id": execution_id,
        "project_id": project_id,
        "status": expected_status,
        "resolution": resolution,
        "evidence_sha256": evidence_sha256,
        "reconciled_by": "operator",
        "reconciled_at": response.json()["reconciled_at"],
    }

    db = SessionLocal()
    try:
        row = db.get(ExecutionRequest, execution_id)
        assert row is not None
        assert row.status == expected_status
        assert row.result_summary["outcome"] == expected_outcome
        audit = (
            db.query(AuditLog)
            .filter(
                AuditLog.resource_id == execution_id,
                AuditLog.action == "execution.outcome_reconciled",
            )
            .one()
        )
        assert audit.after["evidence_sha256"] == evidence_sha256
    finally:
        db.close()


def test_confirmed_not_executed_allows_one_fresh_claim_under_original_bounds():
    db = SessionLocal()
    try:
        row = _execution("outcome_unknown")
        row.actor_digest = content_digest(row.subject)
        row.arguments_digest = content_digest({})
        row.policy_snapshot_digest = content_digest(row.policy_snapshot)
        db.add(row)
        db.flush()
        resolved = resolve_unknown_outcome(
            db,
            row,
            resolution="confirmed_not_executed",
            evidence_sha256="f" * 64,
            reconciled_by="operator",
        )
        assert resolved.status == "approved"
        match = match_and_claim_execution(
            db,
            project_id=row.project_id,
            run_id=row.run_id,
            subject=row.subject,
            server_id=row.server_id,
            tool_name=row.tool_name,
            tool_revision_id=row.tool_revision_id,
            tool_revision_digest=row.tool_revision_digest,
            arguments={},
            policy_snapshot=row.policy_snapshot,
            claimant="worker-one",
            idempotency_key=row.idempotency_key,
        )
        assert match.kind == "claimed"
        duplicate = match_and_claim_execution(
            db,
            project_id=row.project_id,
            run_id=row.run_id,
            subject=row.subject,
            server_id=row.server_id,
            tool_name=row.tool_name,
            tool_revision_id=row.tool_revision_id,
            tool_revision_digest=row.tool_revision_digest,
            arguments={},
            policy_snapshot=row.policy_snapshot,
            claimant="worker-two",
            idempotency_key=row.idempotency_key,
        )
        assert duplicate.kind == "terminal"
    finally:
        db.rollback()
        db.close()


def test_unknown_outcome_resolution_is_single_transition_and_rejects_secret_input():
    db = SessionLocal()
    try:
        row = _execution("outcome_unknown")
        db.add(row)
        db.flush()
        with pytest.raises(ValueError, match="irreversible SHA-256"):
            resolve_unknown_outcome(
                db,
                row,
                resolution="confirmed_succeeded",
                evidence_sha256="sk-abcdefghijklmnopqrstuvwxyz123456",
                reconciled_by="operator",
            )
        resolve_unknown_outcome(
            db,
            row,
            resolution="confirmed_succeeded",
            evidence_sha256="a" * 64,
            reconciled_by="operator",
        )
        with pytest.raises(OutcomeResolutionConflict):
            resolve_unknown_outcome(
                db,
                row,
                resolution="confirmed_failed",
                evidence_sha256="b" * 64,
                reconciled_by="operator",
            )
        db.rollback()
        execution_id = _execution("outcome_unknown").id
    finally:
        db.close()

    secret_canary = "sk-abcdefghijklmnopqrstuvwxyz123456"
    response = client.post(
        f"/v1/executions/{execution_id}/resolve",
        headers=operator_headers,
        json={
            "resolution": "confirmed_succeeded",
            "evidence_sha256": secret_canary,
        },
    )
    assert response.status_code == 422
    assert secret_canary not in response.text


def test_unknown_outcome_resolution_requires_admin_scope():
    db = SessionLocal()
    try:
        row = _execution("outcome_unknown")
        ensure_project(db, row.project_id)
        _, token = create_api_key(db, row.project_id, "read-only-ops", ["jobs:read"])
        db.add(row)
        db.commit()
        execution_id = row.id
    finally:
        db.close()

    response = client.post(
        f"/v1/executions/{execution_id}/resolve",
        headers={"Authorization": f"Bearer {token}"},
        json={"resolution": "confirmed_succeeded", "evidence_sha256": "c" * 64},
    )
    assert response.status_code == 403
    assert token not in response.text


def test_jobs_reader_can_list_unknown_executions_without_sensitive_envelope_fields():
    db = SessionLocal()
    try:
        row = _execution("outcome_unknown")
        row.subject = {"agent_id": "private-agent", "hidden": "private-value"}
        row.policy_snapshot = {"hidden": "private-policy-value"}
        ensure_project(db, row.project_id)
        _, token = create_api_key(db, row.project_id, "incident-reader", ["jobs:read"])
        db.add(row)
        db.commit()
        execution_id = row.id
        project_id = row.project_id
    finally:
        db.close()

    response = client.get(
        "/v1/executions",
        headers={"Authorization": f"Bearer {token}"},
        params={"project_id": project_id, "status": "outcome_unknown"},
    )
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [execution_id]
    item = response.json()[0]
    assert item["arguments_digest"] == "c" * 64
    for forbidden_key in ("subject", "policy_snapshot", "result_summary", "idempotency_key"):
        assert forbidden_key not in item
    for forbidden_value in (
        "private-agent",
        "private-value",
        "private-policy-value",
        token,
    ):
        assert forbidden_value not in response.text


def test_claim_lease_uses_requested_duration_and_can_be_released_once():
    db = SessionLocal()
    try:
        row = _execution("approved")
        row.actor_digest = content_digest(row.subject)
        row.arguments_digest = content_digest({})
        row.policy_snapshot_digest = content_digest(row.policy_snapshot)
        db.add(row)
        db.flush()
        claimed = match_and_claim_execution(
            db,
            project_id=row.project_id,
            run_id=row.run_id,
            subject=row.subject,
            server_id=row.server_id,
            tool_name=row.tool_name,
            tool_revision_id=row.tool_revision_id,
            tool_revision_digest=row.tool_revision_digest,
            arguments={},
            policy_snapshot=row.policy_snapshot,
            claimant="lease-owner",
            idempotency_key=None,
            lease_seconds=75,
        )
        assert claimed.kind == "claimed"
        assert row.lease_expires_at is not None
        lease_expires_at = row.lease_expires_at
        if lease_expires_at.tzinfo is None:
            lease_expires_at = lease_expires_at.replace(tzinfo=UTC)
        assert 70 < (lease_expires_at - datetime.now(UTC)).total_seconds() <= 75
        assert release_execution_claim(db, row) is True
        assert row.status == "approved"
        assert release_execution_claim(db, row) is False
    finally:
        db.rollback()
        db.close()


def test_stale_claimant_cannot_overwrite_reconciled_execution_result():
    first = SessionLocal()
    second = SessionLocal()
    try:
        row = _execution("execution_claimed")
        row.claimed_by = "worker-one"
        first.add(row)
        first.commit()
        execution_id = row.id

        changed = (
            second.query(ExecutionRequest)
            .filter(
                ExecutionRequest.id == execution_id,
                ExecutionRequest.status == "execution_claimed",
            )
            .update({ExecutionRequest.status: "outcome_unknown"}, synchronize_session=False)
        )
        assert changed == 1
        second.commit()

        with pytest.raises(ExecutionClaimConflict):
            mark_execution_result(first, row, {"content": [{"type": "text", "text": "done"}]})
        first.rollback()
    finally:
        first.close()
        second.close()

    db = SessionLocal()
    try:
        stored = db.get(ExecutionRequest, execution_id)
        assert stored is not None
        assert stored.status == "outcome_unknown"
    finally:
        db.close()
