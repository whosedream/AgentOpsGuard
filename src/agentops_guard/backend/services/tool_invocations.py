"""Durable tool receipts. Redis delivers IDs; the database decides who may execute.

An expired dispatch is unknown, not permission to run again. Only a completed
transport attempt on an operator-reviewed read-only tool may be retried.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from typing import Any, Callable
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException
from sqlalchemy import case
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database_resilience import database_http_boundary
from agentops_guard.backend.models import (
    ApiKey,
    BackgroundJob,
    McpServer,
    McpTool,
    McpToolRevision,
    Project,
    ToolExecutionPolicy,
    ToolInvocation,
)
from agentops_guard.backend.security.context import (
    AuthContext,
    clear_auth_context,
    current_auth_context,
    set_auth_context,
)
from agentops_guard.backend.services.api_keys import has_scope
from agentops_guard.backend.services.content import detect_secret_labels, new_id
from agentops_guard.backend.services.jobs import JobLeaseLost, create_job
from agentops_guard.backend.services.mcp_tool_revisions import record_tool_revision
from agentops_guard.gateway.auth import GatewayIdentity

LEASE_SECONDS = 120
QUEUE_TTL_SECONDS = 3600
MAX_DISPATCHES = 3


class InvocationRetry(RuntimeError):
    """Retry the queue delivery, not necessarily the external tool."""


def _now() -> datetime:
    return datetime.now(UTC)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _json(value: Any) -> str:
    # Exact strings: do not normalize Unicode or redact execution arguments.
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: Any) -> str:
    return sha256(_json(value).encode()).hexdigest()


def request_id(value: Any = None) -> str:
    if value is None:
        return str(uuid4())
    try:
        return str(UUID(value)) if isinstance(value, str) else _invalid_id()
    except ValueError:
        return _invalid_id()


def _invalid_id() -> str:
    raise HTTPException(400, "requestId must be a UUID")


def _cipher() -> Fernet:
    key = get_settings().invocation_encryption_key
    if key is None:
        raise HTTPException(503, "Durable invocation encryption is not configured")
    try:
        return Fernet(key.get_secret_value().encode())
    except ValueError:
        raise HTTPException(503, "Durable invocation encryption is invalid") from None


def _policy_value(policy: ToolExecutionPolicy) -> dict:
    value = {
        "revision": policy.revision_digest,
        "queue": policy.queue_enabled,
        "retry": policy.retry_mode,
        "evidence": policy.evidence_sha256,
    }
    if policy.receipt_contract is not None:
        value["receipt"] = policy.receipt_contract
    return value


def current_revision(db: Session, project: str, tool_id: str) -> McpToolRevision:
    tool = db.get(McpTool, tool_id, populate_existing=True)
    server = db.get(McpServer, tool.server_id, populate_existing=True) if tool is not None else None
    if (
        tool is None
        or tool.project_id != project
        or tool.status != "active"
        or server is None
        or server.project_id != project
        or server.status != "active"
    ):
        raise HTTPException(404, "MCP tool not found")
    old = db.get(McpToolRevision, tool.current_revision_id) if tool.current_revision_id else None
    if tool.current_revision_id and old is None:
        raise HTTPException(409, "MCP tool revision is unavailable")
    return record_tool_revision(
        db,
        server,
        tool,
        source=old.descriptor if old else None,
        source_digest=old.source_digest if old else None,
    )


def _reviewed_policy(db: Session, row: ToolInvocation) -> ToolExecutionPolicy:
    revision = current_revision(db, row.project_id, row.tool_id)
    policy = db.get(ToolExecutionPolicy, row.tool_id, populate_existing=True)
    if (
        policy is None
        or policy.project_id != row.project_id
        or not policy.queue_enabled
        or policy.revision_digest != revision.content_digest
    ):
        raise HTTPException(409, "Tool has no current reviewed queue policy")
    if row.revision_digest is not None and (
        row.revision_digest != revision.content_digest
        or row.execution_policy_digest != _digest(_policy_value(policy))
    ):
        raise HTTPException(409, "Queued tool or execution policy changed")
    row.revision_digest = revision.content_digest
    row.execution_policy_digest = _digest(_policy_value(policy))
    return policy


def lookup(db: Session, identity: GatewayIdentity, external_id: str) -> ToolInvocation:
    row = (
        db.query(ToolInvocation)
        .filter_by(
            project_id=identity.project_id,
            actor_digest=_digest(asdict(identity)),
            request_id=request_id(external_id),
        )
        .one_or_none()
    )
    if row is None:
        raise HTTPException(404, "Invocation not found")
    return row


def public_status(row: ToolInvocation) -> dict:
    state = row.status
    if (
        state in {"preparing", "dispatched"}
        and row.lease_expires_at
        and _utc(row.lease_expires_at) < _now()
    ):
        state = (
            "recovering" if state == "preparing" and row.mode == "queued"
            else "outcome_unknown" if state == "dispatched" or row.attempts
            else "not_dispatched"
        )
    if state == "recovering" and _utc(row.expires_at) < _now():
        state = "expired"
    if state in {"queued", "waiting_approval"} and _utc(row.expires_at) < _now():
        state = "expired"
    return {
        "requestId": row.request_id,
        "state": state,
        "mode": row.mode,
        "attempts": row.attempts,
        "summary": row.summary or {},
        "clientMayReplay": False,
        "resultStored": bool(row.encrypted_result and row.result_expires_at
                             and _utc(row.result_expires_at) > _now()),
    }


def register(
    db: Session, payload: dict, identity: GatewayIdentity, *, queued: bool,
    expected_review: tuple[str, str] | None = None,
) -> tuple[ToolInvocation, bool]:
    external_id = request_id(payload.get("requestId"))
    if not all(isinstance(payload.get(k), str) and payload[k] for k in ("serverId", "name")):
        raise HTTPException(400, "name and serverId are required")
    if len(payload["serverId"]) > 64 or len(payload["name"]) > 255:
        raise HTTPException(400, "Tool identifier is too long")
    if not isinstance(payload.get("arguments", {}), dict):
        raise HTTPException(400, "arguments must be an object")
    stable_payload = {k: v for k, v in payload.items() if k != "requestId"}
    try:
        raw = _json(stable_payload)
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid invocation JSON") from None
    if queued and len(raw.encode()) > 65_536:
        raise HTTPException(413, "Invocation payload exceeds 64 KiB")
    existing = (
        db.query(ToolInvocation)
        .filter_by(
            project_id=identity.project_id,
            actor_digest=_digest(asdict(identity)),
            request_id=external_id,
        )
        .one_or_none()
    )
    if existing is not None:
        if existing.payload_digest != _digest(stable_payload) or existing.mode != (
            "queued" if queued else "sync"
        ):
            raise HTTPException(409, "requestId is already bound to another request")
        return existing, False
    row = ToolInvocation(
        id=new_id("inv"),
        project_id=identity.project_id,
        request_id=external_id,
        actor_digest=_digest(asdict(identity)),
        subject=asdict(identity),
        payload_digest=_digest(stable_payload),
        tool_id=f"{payload['serverId']}:{payload['name']}",
        mode="queued" if queued else "sync",
        status="queued" if queued else "pending",
        expires_at=_now() + timedelta(seconds=QUEUE_TTL_SECONDS),
        summary={},
        attempts=0,
        revision_digest=expected_review[0] if expected_review else None,
        execution_policy_digest=expected_review[1] if expected_review else None,
    )
    if queued:
        if identity.auth_kind != "api_key":
            raise HTTPException(403, "Deferred execution requires a persistent project API key")
        if set(detect_secret_labels(raw)) - {"email", "phone"}:
            raise HTTPException(400, "Use credential references, not secret values")
        _reviewed_policy(db, row)
        # Serialize admission on one project row so concurrent senders cannot
        # exceed the backlog bound. This storage must be writable to accept.
        db.query(Project).filter_by(id=row.project_id).with_for_update().one()
        pending = (
            db.query(ToolInvocation)
            .filter(
                ToolInvocation.project_id == row.project_id,
                ToolInvocation.mode == "queued",
                ToolInvocation.status.in_(
                    ["queued", "preparing", "dispatched", "waiting_approval"]
                ),
            )
            .count()
        )
        if pending >= 1000:
            raise HTTPException(429, "Project invocation backlog is full")
        row.encrypted_payload = (
            _cipher()
            .encrypt(
                _json(
                    {
                        "id": row.id,
                        "project": row.project_id,
                        "actor": row.actor_digest,
                        "payload": stable_payload,
                    }
                ).encode()
            )
            .decode()
        )
    # Receipt, encrypted request, job and outbox are acknowledged by ONE commit.
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
            if queued:
                row.job_id = create_job(
                    db, row.project_id, "tool_invocation", {"invocation_id": row.id}
                ).id
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(ToolInvocation)
            .filter_by(
                project_id=identity.project_id,
                actor_digest=_digest(asdict(identity)),
                request_id=external_id,
            )
            .one_or_none()
        )
        if existing is None:
            raise
        if existing.payload_digest != row.payload_digest or existing.mode != row.mode:
            raise HTTPException(409, "requestId is already bound to another request") from None
        return existing, False
    return row, True


def _lock_job_claim(db: Session, claim: tuple[str, str] | None) -> None:
    if claim is None:
        return  # Synchronous calls have no background job.
    job = db.query(BackgroundJob).filter(
        BackgroundJob.id == claim[0],
        BackgroundJob.status == "running",
        BackgroundJob.lease_owner == claim[1],
        BackgroundJob.lease_expires_at > _now(),
    ).with_for_update().populate_existing().one_or_none()
    if job is None:
        raise JobLeaseLost("Background execution ownership lost")


class InvocationAttempt:
    def __init__(self, row: ToolInvocation, token: str, job_claim: tuple[str, str] | None = None):
        self.id = row.id
        self.token = token
        self.dispatched = False
        self.job_claim = job_claim

    def dispatch(self, db: Session, revision_digest: str) -> None:
        # Lock order is always job -> invocation, also used by recovery. A
        # stale worker cannot claim/dispatch after the job changes owners.
        _lock_job_claim(db, self.job_claim)
        now = _now()
        row = db.get(ToolInvocation, self.id)
        if row.receipt_binding is not None:
            from agentops_guard.backend.services.tool_receipts import reviewed_binding

            reviewed_binding(db, row)
            if row.receipt_binding["revision"] != revision_digest:
                raise HTTPException(409, "Receipt tool revision changed before dispatch")
        if row.mode == "queued":
            queued_identity(db, row)
            _reviewed_policy(db, row)
            if row.revision_digest != revision_digest:
                raise HTTPException(409, "Queued tool revision changed")
        changed = (
            db.query(ToolInvocation)
            .filter(
                ToolInvocation.id == self.id,
                ToolInvocation.lease_token == self.token,
                ToolInvocation.status == "preparing",
                ToolInvocation.lease_expires_at > now,
                ToolInvocation.expires_at > now,
            )
            .update(
                {
                    "status": "dispatched",
                    "attempts": ToolInvocation.attempts + 1,
                    "revision_digest": revision_digest,
                    "lease_expires_at": now
                    + timedelta(
                        seconds=max(LEASE_SECONDS, get_settings().gateway_call_timeout_seconds + 60)
                    ),
                    "updated_at": now,
                },
                synchronize_session=False,
            )
        )
        if changed != 1:
            raise HTTPException(409, "Invocation lease lost; tool was not dispatched")
        db.commit()  # A failed/ambiguous commit MUST NOT dispatch.
        self.dispatched = True


def _finish(db: Session, attempt: InvocationAttempt, state: str, summary: dict) -> None:
    _lock_job_claim(db, attempt.job_claim)
    values = {
        "status": state,
        "summary": summary,
        "lease_token": None,
        "lease_expires_at": None,
        "updated_at": _now(),
    }
    if state not in {"queued", "waiting_approval"}:
        values["encrypted_payload"] = None
    changed = (
        db.query(ToolInvocation)
        .filter_by(id=attempt.id, lease_token=attempt.token)
        .update(values, synchronize_session=False)
    )
    if changed != 1:
        raise HTTPException(409, "Invocation lease lost; result was not released")
    db.commit()


def execute(
    db: Session,
    row: ToolInvocation,
    payload: dict,
    identity: GatewayIdentity,
    perform: Callable,
    *,
    queued: bool = False,
    job_claim: tuple[str, str] | None = None,
) -> dict:
    _lock_job_claim(db, job_claim)
    now = _now()
    token = str(uuid4())
    claimed = (
        db.query(ToolInvocation)
        .filter(
            ToolInvocation.id == row.id,
            (ToolInvocation.status.in_(["pending", "queued"]))
            | ((ToolInvocation.status == "preparing") & (ToolInvocation.lease_expires_at < now)),
            ToolInvocation.expires_at > now,
        )
        .update(
            {
                "status": "preparing",
                "lease_token": token,
                "lease_expires_at": now + timedelta(seconds=LEASE_SECONDS),
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    if claimed != 1:
        db.refresh(row)
        if queued and row.status == "preparing" and _utc(row.lease_expires_at) >= now:
            raise InvocationRetry("Invocation is still preparing")
        return {
            "isError": True,
            "content": [{"type": "text", "text": "invocation_already_recorded"}],
            "invocation": public_status(row),
        }
    attempt = InvocationAttempt(row, token, job_claim)
    try:
        from agentops_guard.backend.services.tool_receipts import prepare_payload

        payload = prepare_payload(db, row, payload)
        result = perform(payload, identity, db, invocation_attempt=attempt)
    except HTTPException as exc:
        db.rollback()
        db.refresh(row)
        state = "outcome_unknown" if row.status == "dispatched" else "failed"
        retry = queued and row.status == "preparing" and exc.status_code in {429, 503}
        _finish(db, attempt, "queued" if retry else state, {"httpStatus": exc.status_code})
        if retry:
            raise InvocationRetry("Pre-dispatch dependency unavailable") from None
        raise
    state = (
        "outcome_unknown"
        if result.get("upstreamError")
        else "waiting_approval"
        if result.get("approvalRequestId") and not attempt.dispatched
        else "failed"
        if result.get("isError")
        else "succeeded"
    )
    db.refresh(row)
    summary = {
        "toolResponseReceived": attempt.dispatched and not bool(result.get("upstreamError")),
        "isError": bool(result.get("isError")),
    }
    for field in ("approvalRequestId", "executionRequestId"):
        if state == "waiting_approval" and result.get(field):
            summary[field] = result[field]
    if isinstance(result.get("policyDecision"), dict) and result["policyDecision"].get("id"):
        summary["policyDecisionId"] = result["policyDecision"]["id"]
    retry = False
    if queued and state == "outcome_unknown" and row.attempts < MAX_DISPATCHES:
        # The transport has returned and cleaned up. Worker-loss is NOT this path.
        policy = _reviewed_policy(db, row)
        retry = policy.retry_mode == "read_only" and _utc(row.expires_at) > _now()
    with database_http_boundary(
        tool_execution={
            "state": "outcome_unknown" if result.get("upstreamError") else "response_received",
            "tool_reported_error": None
            if result.get("upstreamError")
            else bool(result.get("isError")),
            "result_released": False,
            "automatic_retry_allowed": False,
        }
        if row.attempts
        else None
    ):
        _finish(db, attempt, "queued" if retry else state, summary)
    if retry:
        raise InvocationRetry("Reviewed read-only transport attempt may be retried")
    db.refresh(row)
    result["invocation"] = public_status(row)
    return result


def queued_identity(db: Session, row: ToolInvocation) -> GatewayIdentity:
    identity = GatewayIdentity(**row.subject)
    key = db.get(ApiKey, identity.actor_id, populate_existing=True)
    project = db.get(Project, row.project_id, populate_existing=True)
    if (
        identity.auth_kind != "api_key"
        or identity.project_id != row.project_id
        or _digest(asdict(identity)) != row.actor_digest
        or key is None
        or key.project_id != row.project_id
        or key.revoked_at is not None
        or (key.expires_at and _utc(key.expires_at) <= _now())
        or key.agent_id != identity.agent_id
        or not has_scope(key, "mcp:invoke")
        or project is None
        or project.status != "active"
    ):
        raise HTTPException(403, "Deferred execution authority is no longer valid")
    set_auth_context(
        AuthContext(
            kind="api_key",
            project_id=row.project_id,
            organization_id=project.organization_id,
            scopes=key.scopes,
            capabilities=key.scopes,
            key_id=key.id,
            actor_id=key.id,
            agent_id=key.agent_id,
        )
    )
    return identity


def execute_queued(db: Session, job: BackgroundJob, *, claimant: str) -> dict:
    from agentops_guard.gateway.app import _perform_tools_call

    # Do not adopt lease_owner from a refreshed ORM row: the original worker
    # identity must survive a pause and another worker's takeover.
    claim = (job.id, claimant)
    _lock_job_claim(db, claim)
    row = db.get(ToolInvocation, job.payload["invocation_id"], populate_existing=True)
    if row is None or row.project_id != job.project_id or row.job_id != job.id:
        raise ValueError("Invocation job binding is invalid")
    if row.status not in {"queued", "preparing"}:
        return public_status(row)  # Including dispatched/unknown: NEVER blindly replay.
    previous_auth = current_auth_context()
    try:
        if _utc(row.expires_at) <= _now():
            raise HTTPException(410, "Queued invocation expired")
        identity = queued_identity(db, row)
        _reviewed_policy(db, row)
        try:
            envelope = json.loads(_cipher().decrypt(row.encrypted_payload.encode()))
        except (InvalidToken, UnicodeError, ValueError):
            raise HTTPException(409, "Queued payload cannot be authenticated") from None
        if (
            envelope.get("id") != row.id
            or envelope.get("project") != row.project_id
            or envelope.get("actor") != row.actor_digest
            or _digest(envelope.get("payload")) != row.payload_digest
        ):
            raise HTTPException(409, "Queued payload binding is invalid")
        execute(db, row, envelope["payload"], identity, _perform_tools_call, queued=True, job_claim=claim)
        db.refresh(row)
        return public_status(row)
    except HTTPException as exc:
        db.rollback()
        _lock_job_claim(db, claim)
        db.refresh(row)
        # Do not overwrite another executor or a durable dispatch marker.
        db.query(ToolInvocation).filter(
            ToolInvocation.id == row.id,
            (ToolInvocation.status == "queued")
            | ((ToolInvocation.status == "preparing") & (ToolInvocation.lease_expires_at < _now())),
        ).update(
            {
                "status": "expired" if exc.status_code == 410 else "failed",
                "summary": {"httpStatus": exc.status_code},
                "encrypted_payload": None,
                "lease_token": None,
                "updated_at": _now(),
            },
            synchronize_session=False,
        )
        db.commit()
        db.refresh(row)
        return public_status(row)
    finally:
        set_auth_context(previous_auth) if previous_auth is not None else clear_auth_context()


def recover_job_invocation(db: Session, job: BackgroundJob, *, exhausted: bool) -> dict | None:
    """Called with the job locked: fence its old attempt before re-delivery.

    Returning a terminal receipt settles the job without another tool attempt.
    A missing response after dispatch is unknown, even for reviewed reads.
    """
    row = db.query(ToolInvocation).filter_by(
        id=job.payload["invocation_id"], project_id=job.project_id,
    ).with_for_update().populate_existing().one_or_none()
    if row is None:
        raise ValueError("Invocation job binding is invalid during recovery")
    if row.job_id != job.id:
        # An approval resume creates a new job. Settle the old delivery without
        # changing the resumed invocation or borrowing the new job's authority.
        return {**public_status(row), "superseded": True}
    if row.status not in {"queued", "preparing", "dispatched"}:
        return public_status(row)
    if row.status == "dispatched":
        row.status = "outcome_unknown"
        row.summary = {"code": "worker_lost_after_dispatch"}
    elif _utc(row.expires_at) <= _now():
        row.status = "expired"
        row.summary = {"code": "queued_request_expired"}
    elif exhausted:
        row.status = "outcome_unknown" if row.attempts else "not_dispatched"
        row.summary = {"code": "delivery_attempts_exhausted"}
    else:
        row.status = "queued"
    row.lease_token = None
    row.lease_expires_at = None
    row.updated_at = _now()
    if row.status != "queued":
        row.encrypted_payload = None
        return public_status(row)
    return None


def resume(db: Session, row: ToolInvocation) -> dict:
    changed = (
        db.query(ToolInvocation)
        .filter(
            ToolInvocation.id == row.id,
            ToolInvocation.mode == "queued",
            ToolInvocation.status == "waiting_approval",
            ToolInvocation.expires_at > _now(),
        )
        .update({"status": "queued", "updated_at": _now()}, synchronize_session=False)
    )
    if changed != 1:
        raise HTTPException(409, "Only an unexpired queued approval wait can be resumed")
    # This is NOT approval: the full gateway pipeline claims the actual approval later.
    db.refresh(row)
    row.job_id = create_job(db, row.project_id, "tool_invocation", {"invocation_id": row.id}).id
    db.commit()
    return public_status(row)


def reconcile_invocations(db: Session) -> int:
    """Expire ambiguous receipts without creating a new tool attempt."""
    now = _now()
    changed = 0
    for state, terminal in (("dispatched", "outcome_unknown"), ("preparing", "not_dispatched")):
        # Queue preparations may be safely reclaimed by the existing job retry.
        query = db.query(ToolInvocation).filter(
            ToolInvocation.status == state, ToolInvocation.lease_expires_at < now
        )
        if state == "preparing":
            query = query.filter(ToolInvocation.mode == "sync")
        changed += query.update(
            {"status": terminal, "lease_token": None, "encrypted_payload": None, "updated_at": now},
            synchronize_session=False,
        )
    changed += (
        db.query(ToolInvocation)
        .filter(
            ToolInvocation.status.in_(["queued", "waiting_approval", "pending"]),
            ToolInvocation.expires_at <= now,
        )
        .update(
            {"status": "expired", "encrypted_payload": None, "updated_at": now},
            synchronize_session=False,
        )
    )
    dead_ids = db.query(BackgroundJob.id).filter(
        BackgroundJob.kind == "tool_invocation", BackgroundJob.status == "dead"
    )
    changed += (
        db.query(ToolInvocation)
        .filter(
            ToolInvocation.job_id.in_(dead_ids),
            (ToolInvocation.status == "queued")
            | ((ToolInvocation.status == "preparing") & (ToolInvocation.lease_expires_at < now)),
        )
        .update(
            {
                "status": case(
                    (ToolInvocation.attempts > 0, "outcome_unknown"), else_="not_dispatched"
                ),
                "encrypted_payload": None,
                "lease_token": None,
                "summary": {"code": "delivery_attempts_exhausted"},
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    return changed
