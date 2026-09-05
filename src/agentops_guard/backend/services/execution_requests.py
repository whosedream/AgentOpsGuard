from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import re
from typing import Any, Literal

from sqlalchemy.orm import Session

from agentops_guard.backend.models import ApprovalRequest, ExecutionRequest
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.mcp_tool_revisions import content_digest


ExecutionMatchKind = Literal[
    "none",
    "waiting",
    "claimed",
    "stale",
    "terminal",
]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ExecutionMatch:
    kind: ExecutionMatchKind
    request: ExecutionRequest | None = None


class OutcomeResolutionConflict(ValueError):
    pass


class ExecutionClaimConflict(ValueError):
    pass


def create_execution_request(
    db: Session,
    *,
    approval: ApprovalRequest,
    decision_id: str,
    project_id: str,
    run_id: str | None,
    subject: dict[str, Any],
    server_id: str,
    tool_name: str,
    tool_revision_id: str,
    tool_revision_digest: str,
    arguments: dict[str, Any],
    intent_ref: str | None,
    policy_snapshot: dict[str, Any],
    risk_score: float,
    risk_labels: list[str],
    idempotency_key: str | None,
) -> ExecutionRequest:
    now = datetime.now(UTC)
    expires_at = approval.expires_at or now + timedelta(minutes=15)
    row = ExecutionRequest(
        id=new_id("exec"),
        project_id=project_id,
        run_id=run_id,
        decision_id=decision_id,
        approval_id=approval.id,
        subject=subject,
        actor_digest=content_digest(subject),
        server_id=server_id,
        tool_name=tool_name,
        tool_revision_id=tool_revision_id,
        tool_revision_digest=tool_revision_digest,
        arguments_digest=content_digest(arguments),
        intent_ref=intent_ref,
        policy_snapshot=policy_snapshot,
        policy_snapshot_digest=content_digest(policy_snapshot),
        risk_score=risk_score,
        risk_labels=risk_labels,
        idempotency_key=idempotency_key,
        status="waiting_approval",
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()
    approval.execution_request_id = row.id
    approval.expires_at = expires_at
    return row


def match_and_claim_execution(
    db: Session,
    *,
    project_id: str,
    run_id: str | None,
    subject: dict[str, Any],
    server_id: str,
    tool_name: str,
    tool_revision_id: str,
    tool_revision_digest: str,
    arguments: dict[str, Any],
    policy_snapshot: dict[str, Any],
    claimant: str,
    idempotency_key: str | None,
    lease_seconds: float = 60.0,
) -> ExecutionMatch:
    if lease_seconds <= 0:
        raise ValueError("Execution lease must be positive")
    query = db.query(ExecutionRequest).filter(
        ExecutionRequest.project_id == project_id,
        ExecutionRequest.run_id == run_id,
        ExecutionRequest.actor_digest == content_digest(subject),
        ExecutionRequest.server_id == server_id,
        ExecutionRequest.tool_name == tool_name,
        ExecutionRequest.arguments_digest == content_digest(arguments),
    )
    if idempotency_key is not None:
        query = query.filter(ExecutionRequest.idempotency_key == idempotency_key)
    row = query.order_by(ExecutionRequest.created_at.desc()).first()
    if row is None:
        return ExecutionMatch("none")

    now = datetime.now(UTC)
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= now and row.status in {"waiting_approval", "approved"}:
        row.status = "expired"
        approval = db.get(ApprovalRequest, row.approval_id)
        if approval is not None and approval.status == "pending":
            approval.status = "expired"
            approval.resolved_at = now
        db.flush()
        return ExecutionMatch("terminal", row)

    expected_policy_digest = content_digest(policy_snapshot)
    if (
        row.tool_revision_id != tool_revision_id
        or row.tool_revision_digest != tool_revision_digest
        or row.policy_snapshot_digest != expected_policy_digest
    ) and row.status in {"waiting_approval", "approved"}:
        row.status = "stale"
        approval = db.get(ApprovalRequest, row.approval_id)
        if approval is not None and approval.status == "pending":
            approval.status = "stale"
            approval.resolved_at = now
        db.flush()
        return ExecutionMatch("stale", row)

    if row.status == "waiting_approval":
        return ExecutionMatch("waiting", row)
    if row.status != "approved":
        return ExecutionMatch("terminal", row)

    claimed = (
        db.query(ExecutionRequest)
        .filter(
            ExecutionRequest.id == row.id,
            ExecutionRequest.status == "approved",
        )
        .update(
            {
                ExecutionRequest.status: "execution_claimed",
                ExecutionRequest.claimed_by: claimant,
                ExecutionRequest.claimed_at: now,
                ExecutionRequest.lease_expires_at: now + timedelta(seconds=lease_seconds),
            },
            synchronize_session=False,
        )
    )
    if claimed != 1:
        return ExecutionMatch("terminal", row)
    db.flush()
    db.refresh(row)
    return ExecutionMatch("claimed", row)


def mark_execution_result(
    db: Session,
    row: ExecutionRequest,
    result: dict[str, Any],
) -> None:
    if row.status != "execution_claimed":
        raise ValueError("Execution request is not claimed")
    upstream_error = result.get("upstreamError")
    if upstream_error:
        status = "outcome_unknown"
        result_summary = {"is_error": True, "outcome": "unknown"}
    elif result.get("isError"):
        status = "failed"
        result_summary = {"is_error": True, "outcome": "failed"}
    else:
        status = "succeeded"
        result_summary = {"is_error": False, "outcome": "succeeded"}
    completed_at = datetime.now(UTC)
    updated = (
        db.query(ExecutionRequest)
        .filter(
            ExecutionRequest.id == row.id,
            ExecutionRequest.status == "execution_claimed",
            ExecutionRequest.claimed_by == row.claimed_by,
        )
        .update(
            {
                ExecutionRequest.status: status,
                ExecutionRequest.result_summary: result_summary,
                ExecutionRequest.completed_at: completed_at,
                ExecutionRequest.lease_expires_at: None,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        raise ExecutionClaimConflict("Execution claim is no longer current")
    db.flush()
    db.refresh(row)


def release_execution_claim(db: Session, row: ExecutionRequest) -> bool:
    if row.status != "execution_claimed":
        return False
    released = (
        db.query(ExecutionRequest)
        .filter(
            ExecutionRequest.id == row.id,
            ExecutionRequest.status == "execution_claimed",
            ExecutionRequest.claimed_by == row.claimed_by,
        )
        .update(
            {
                ExecutionRequest.status: "approved",
                ExecutionRequest.claimed_by: None,
                ExecutionRequest.claimed_at: None,
                ExecutionRequest.lease_expires_at: None,
            },
            synchronize_session=False,
        )
    )
    db.flush()
    if released == 1:
        db.refresh(row)
        return True
    return False


def reconcile_execution_leases(db: Session) -> int:
    now = datetime.now(UTC)
    rows = (
        db.query(ExecutionRequest)
        .filter(
            ExecutionRequest.status == "execution_claimed",
            ExecutionRequest.lease_expires_at < now,
        )
        .all()
    )
    for row in rows:
        row.status = "outcome_unknown"
        row.completed_at = now
        row.result_summary = {
            "is_error": True,
            "outcome": "unknown",
            "reason": "execution_lease_expired",
        }
    db.flush()
    return len(rows)


def resolve_unknown_outcome(
    db: Session,
    row: ExecutionRequest,
    *,
    resolution: str,
    evidence_sha256: str,
    reconciled_by: str,
) -> ExecutionRequest:
    if _SHA256.fullmatch(evidence_sha256) is None:
        raise ValueError("Outcome evidence must be an irreversible SHA-256 digest")
    transitions = {
        "confirmed_succeeded": ("succeeded", False, "succeeded"),
        "confirmed_failed": ("failed", True, "failed"),
        "confirmed_not_executed": ("approved", False, "not_executed"),
    }
    try:
        target_status, is_error, outcome = transitions[resolution]
    except KeyError:
        raise ValueError("Unsupported outcome resolution") from None

    now = datetime.now(UTC)
    completed_at = None if resolution == "confirmed_not_executed" else now
    updated = (
        db.query(ExecutionRequest)
        .filter(
            ExecutionRequest.id == row.id,
            ExecutionRequest.status == "outcome_unknown",
        )
        .update(
            {
                ExecutionRequest.status: target_status,
                ExecutionRequest.claimed_by: None,
                ExecutionRequest.claimed_at: None,
                ExecutionRequest.lease_expires_at: None,
                ExecutionRequest.completed_at: completed_at,
                ExecutionRequest.result_summary: {
                    "is_error": is_error,
                    "outcome": outcome,
                    "resolution": "operator_verified",
                },
                ExecutionRequest.reconciliation_resolution: resolution,
                ExecutionRequest.reconciliation_evidence_sha256: evidence_sha256,
                ExecutionRequest.reconciled_by: reconciled_by,
                ExecutionRequest.reconciled_at: now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        raise OutcomeResolutionConflict("Execution outcome is no longer unknown")
    db.flush()
    db.refresh(row)
    record_audit(
        db,
        project_id=row.project_id,
        action="execution.outcome_reconciled",
        resource_type="execution_request",
        resource_id=row.id,
        before={"status": "outcome_unknown"},
        after={
            "status": row.status,
            "resolution": resolution,
            "evidence_sha256": evidence_sha256,
        },
    )
    return row
