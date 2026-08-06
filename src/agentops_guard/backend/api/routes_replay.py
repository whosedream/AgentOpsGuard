from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import job_out, replay_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ReplayRun
from agentops_guard.backend.schemas import JobOut, PageOut, ReplayCreate, ReplayOut
from agentops_guard.backend.services.jobs import QueueUnavailable, create_job, enqueue_job
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.replay import create_replay


v1_router = APIRouter()


@v1_router.get("/replays", response_model=list[ReplayOut] | PageOut)
def list_replays(project_id: str = "default", source_run_id: str | None = None, limit: int = Query(default=50, le=200), cursor: str | None = None, page_mode: str | None = None, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[ReplayOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(ReplayRun).filter(ReplayRun.project_id == project_id)
    if source_run_id:
        query = query.filter(ReplayRun.source_run_id == source_run_id)
    rows = query.order_by(ReplayRun.created_at.desc()).offset(offset).limit(limit).all()
    items = [replay_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.post("/replays/jobs", response_model=JobOut)
def enqueue_replay(payload: ReplayCreate, request: Request, db: Session = Depends(get_db)) -> JobOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    ensure_project(db, payload.project_id)
    row = create_job(db, payload.project_id, "replay", payload.model_dump())
    try:
        enqueue_job(db, row)
    except QueueUnavailable as exc:
        db.rollback()
        raise HTTPException(503, f"Redis queue unavailable: {exc}") from exc
    db.commit()
    db.refresh(row)
    return job_out(row)


@v1_router.post("/replays", response_model=ReplayOut)
def replay(payload: ReplayCreate, request: Request, db: Session = Depends(get_db)) -> ReplayOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    result = create_replay(db, payload)
    db.commit()
    return result


@v1_router.get("/replays/{replay_id}", response_model=ReplayOut)
def get_replay(replay_id: str, request: Request, db: Session = Depends(get_db)) -> ReplayOut:
    row = db.get(ReplayRun, replay_id)
    if not row:
        raise HTTPException(404, "Replay not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    return replay_out(row)
