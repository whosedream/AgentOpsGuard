from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import (
    AuthContext,
    authorize_project_access,
    get_auth_context,
    require_scope,
)
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import job_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import BackgroundJob, ExecutionRequest
from agentops_guard.backend.schemas import (
    ExecutionOutcomeResolution,
    ExecutionOutcomeResolutionOut,
    ExecutionRequestOut,
    JobOut,
    JobReconciliationOut,
    PageOut,
)
from agentops_guard.backend.services.execution_requests import (
    OutcomeResolutionConflict,
    resolve_unknown_outcome,
)
from agentops_guard.backend.services.jobs import background_job_reconciliation, retry_dead_job


v1_router = APIRouter()


@v1_router.get(
    "/executions",
    response_model=list[ExecutionRequestOut] | PageOut,
    dependencies=[Depends(require_scope("jobs:read"))],
)
def list_executions(
    project_id: str = "default",
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[ExecutionRequestOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(ExecutionRequest).filter(ExecutionRequest.project_id == project_id)
    if status:
        query = query.filter(ExecutionRequest.status == status)
    rows = query.order_by(ExecutionRequest.created_at.desc()).offset(offset).limit(limit).all()
    items = [ExecutionRequestOut.model_validate(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get(
    "/jobs/reconciliation",
    response_model=JobReconciliationOut,
    dependencies=[Depends(require_scope("jobs:read"))],
)
def reconcile_jobs_report(
    project_id: str = "default",
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> JobReconciliationOut:
    authorize_project_access(auth, project_id, db=db)
    return JobReconciliationOut.model_validate(
        background_job_reconciliation(db, project_id=project_id)
    )


@v1_router.get(
    "/jobs",
    response_model=list[JobOut] | PageOut,
    dependencies=[Depends(require_scope("jobs:read"))],
)
def list_jobs(
    project_id: str = "default",
    kind: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[JobOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(BackgroundJob).filter(BackgroundJob.project_id == project_id)
    if kind:
        query = query.filter(BackgroundJob.kind == kind)
    if status:
        query = query.filter(BackgroundJob.status == status)
    rows = query.order_by(BackgroundJob.created_at.desc()).offset(offset).limit(limit).all()
    items = [job_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get(
    "/jobs/{job_id}", response_model=JobOut, dependencies=[Depends(require_scope("jobs:read"))]
)
def get_job(job_id: str, request: Request, db: Session = Depends(get_db)) -> JobOut:
    row = db.get(BackgroundJob, job_id)
    if not row:
        raise HTTPException(404, "Job not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    return job_out(row)


@v1_router.post(
    "/jobs/{job_id}/retry",
    response_model=JobOut,
    dependencies=[Depends(require_scope("jobs:admin"))],
)
def retry_job(job_id: str, request: Request, db: Session = Depends(get_db)) -> JobOut:
    row = db.get(BackgroundJob, job_id)
    if not row:
        raise HTTPException(404, "Job not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    try:
        retried = retry_dead_job(db, row)
    except ValueError as exc:
        raise HTTPException(409, "Job is not eligible for retry") from exc
    db.commit()
    db.refresh(retried)
    return job_out(retried)


@v1_router.post(
    "/executions/{execution_id}/resolve",
    response_model=ExecutionOutcomeResolutionOut,
    dependencies=[Depends(require_scope("jobs:admin"))],
)
def resolve_execution_outcome(
    execution_id: str,
    payload: ExecutionOutcomeResolution,
    request: Request,
    db: Session = Depends(get_db),
) -> ExecutionOutcomeResolutionOut:
    row = db.get(ExecutionRequest, execution_id)
    if row is None:
        raise HTTPException(404, "Execution request not found")
    auth = get_auth_context(request)
    authorize_project_access(auth, row.project_id, conceal=True, db=db)
    try:
        resolved = resolve_unknown_outcome(
            db,
            row,
            resolution=payload.resolution,
            evidence_sha256=payload.evidence_sha256,
            reconciled_by=auth.actor_id or "unknown",
        )
    except OutcomeResolutionConflict as exc:
        raise HTTPException(409, "Execution outcome is not eligible for reconciliation") from exc
    db.commit()
    db.refresh(resolved)
    return ExecutionOutcomeResolutionOut(
        id=resolved.id,
        project_id=resolved.project_id,
        status=resolved.status,
        resolution=resolved.reconciliation_resolution or payload.resolution,
        evidence_sha256=resolved.reconciliation_evidence_sha256 or payload.evidence_sha256,
        reconciled_by=resolved.reconciled_by or "unknown",
        reconciled_at=resolved.reconciled_at,
    )
