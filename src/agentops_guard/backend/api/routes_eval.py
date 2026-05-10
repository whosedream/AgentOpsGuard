from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import eval_run_out, job_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import EvalRun, EvalSuite
from agentops_guard.backend.schemas import EvalRunCreate, EvalRunOut, EvalSuiteCreate, EvalSuiteOut, JobOut, PageOut
from agentops_guard.backend.services.eval import create_eval_suite, run_eval
from agentops_guard.backend.services.jobs import QueueUnavailable, create_job, enqueue_job
from agentops_guard.backend.services.projects import ensure_project


v1_router = APIRouter()


@v1_router.post("/eval-suites", response_model=EvalSuiteOut)
def create_suite(payload: EvalSuiteCreate, request: Request, db: Session = Depends(get_db)) -> EvalSuiteOut:
    authorize_project_access(get_auth_context(request), payload.project_id)
    ensure_project(db, payload.project_id)
    result = create_eval_suite(db, payload)
    db.commit()
    return result


@v1_router.get("/eval-suites", response_model=list[EvalSuiteOut])
def list_suites(project_id: str = "default", auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[EvalSuiteOut]:
    authorize_project_access(auth, project_id)
    rows = db.query(EvalSuite).filter(EvalSuite.project_id == project_id).order_by(EvalSuite.created_at.desc()).all()
    return [EvalSuiteOut(id=row.id, project_id=row.project_id, name=row.name, description=row.description, cases=row.cases, created_at=row.created_at) for row in rows]


@v1_router.get("/eval-runs", response_model=list[EvalRunOut] | PageOut)
def list_eval_runs(project_id: str = "default", suite_id: str | None = None, limit: int = Query(default=50, le=200), cursor: str | None = None, page_mode: str | None = None, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[EvalRunOut] | PageOut:
    authorize_project_access(auth, project_id)
    offset = int(cursor or 0)
    query = db.query(EvalRun).filter(EvalRun.project_id == project_id)
    if suite_id:
        query = query.filter(EvalRun.suite_id == suite_id)
    rows = query.order_by(EvalRun.created_at.desc()).offset(offset).limit(limit).all()
    items = [eval_run_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.post("/eval-suites/{suite_id}/run", response_model=EvalRunOut)
def run_suite_shortcut(suite_id: str, request: Request, db: Session = Depends(get_db)) -> EvalRunOut:
    suite = db.get(EvalSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Eval suite not found")
    authorize_project_access(get_auth_context(request), suite.project_id, conceal=True)
    result = run_eval(db, EvalRunCreate(project_id=suite.project_id, suite_id=suite.id))
    db.commit()
    return result


@v1_router.post("/eval-suites/{suite_id}/jobs", response_model=JobOut)
def enqueue_suite_run(suite_id: str, request: Request, db: Session = Depends(get_db)) -> JobOut:
    suite = db.get(EvalSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Eval suite not found")
    authorize_project_access(get_auth_context(request), suite.project_id, conceal=True)
    payload = EvalRunCreate(project_id=suite.project_id, suite_id=suite.id).model_dump()
    row = create_job(db, suite.project_id, "eval_run", payload)
    try:
        enqueue_job(db, row)
    except QueueUnavailable as exc:
        db.rollback()
        raise HTTPException(503, f"Redis queue unavailable: {exc}") from exc
    db.commit()
    db.refresh(row)
    return job_out(row)


@v1_router.post("/eval-runs", response_model=EvalRunOut)
def create_eval_run(payload: EvalRunCreate, request: Request, db: Session = Depends(get_db)) -> EvalRunOut:
    authorize_project_access(get_auth_context(request), payload.project_id)
    result = run_eval(db, payload)
    db.commit()
    return result


@v1_router.post("/eval-runs/jobs", response_model=JobOut)
def enqueue_eval_run(payload: EvalRunCreate, request: Request, db: Session = Depends(get_db)) -> JobOut:
    authorize_project_access(get_auth_context(request), payload.project_id)
    ensure_project(db, payload.project_id)
    row = create_job(db, payload.project_id, "eval_run", payload.model_dump())
    try:
        enqueue_job(db, row)
    except QueueUnavailable as exc:
        db.rollback()
        raise HTTPException(503, f"Redis queue unavailable: {exc}") from exc
    db.commit()
    db.refresh(row)
    return job_out(row)


@v1_router.get("/eval-runs/{eval_run_id}", response_model=EvalRunOut)
def get_eval_run(eval_run_id: str, request: Request, db: Session = Depends(get_db)) -> EvalRunOut:
    row = db.get(EvalRun, eval_run_id)
    if not row:
        raise HTTPException(404, "Eval run not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True)
    return eval_run_out(row)
