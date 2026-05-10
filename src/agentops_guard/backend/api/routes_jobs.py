from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context, require_scope
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import job_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import BackgroundJob
from agentops_guard.backend.schemas import JobOut, PageOut


v1_router = APIRouter()


@v1_router.get("/jobs", response_model=list[JobOut] | PageOut, dependencies=[Depends(require_scope("jobs:read"))])
def list_jobs(project_id: str = "default", kind: str | None = None, limit: int = Query(default=50, le=200), cursor: str | None = None, page_mode: str | None = None, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[JobOut] | PageOut:
    authorize_project_access(auth, project_id)
    offset = int(cursor or 0)
    query = db.query(BackgroundJob).filter(BackgroundJob.project_id == project_id)
    if kind:
        query = query.filter(BackgroundJob.kind == kind)
    rows = query.order_by(BackgroundJob.created_at.desc()).offset(offset).limit(limit).all()
    items = [job_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get("/jobs/{job_id}", response_model=JobOut, dependencies=[Depends(require_scope("jobs:read"))])
def get_job(job_id: str, request: Request, db: Session = Depends(get_db)) -> JobOut:
    row = db.get(BackgroundJob, job_id)
    if not row:
        raise HTTPException(404, "Job not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True)
    return job_out(row)
