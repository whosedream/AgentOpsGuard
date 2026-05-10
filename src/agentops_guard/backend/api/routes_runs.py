from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import event_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ContentObject, RiskEvent, Run, TraceEvent
from agentops_guard.backend.schemas import ContentOut, EventsIn, PageOut, RunCreate, RunDag, RunOut, RunUpdate, TraceEventOut
from agentops_guard.backend.services.content import new_id, persist_content
from agentops_guard.backend.services.projects import ensure_project, project_for_resource
from agentops_guard.backend.services.trace import build_dag, run_to_schema


v1_router = APIRouter()


@v1_router.post("/runs", response_model=RunOut)
def create_run(payload: RunCreate, request: Request, db: Session = Depends(get_db)) -> RunOut:
    authorize_project_access(get_auth_context(request), payload.project_id)
    ensure_project(db, payload.project_id)
    input_ref = persist_content(db, payload.project_id, payload.input)
    run = Run(id=new_id("run"), project_id=payload.project_id, agent_id=payload.agent_id, trace_id=new_id("trace"), name=payload.name, user_id=payload.user_id, input_ref=input_ref, metadata_json=payload.metadata)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run_to_schema(run)


@v1_router.patch("/runs/{run_id}", response_model=RunOut)
def update_run(run_id: str, payload: RunUpdate, request: Request, db: Session = Depends(get_db)) -> RunOut:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    authorize_project_access(get_auth_context(request), run.project_id, conceal=True)
    if payload.status is not None:
        run.status = payload.status
        if payload.status in {"completed", "failed", "blocked"}:
            run.ended_at = datetime.now(UTC)
    if payload.output is not None:
        run.output_ref = persist_content(db, run.project_id, payload.output)
    if payload.risk is not None:
        run.risk_score = payload.risk.score
        run.risk_labels = payload.risk.labels
    if payload.total_cost_usd is not None:
        run.total_cost_usd = payload.total_cost_usd
    if payload.total_tokens is not None:
        run.total_tokens = payload.total_tokens
    if payload.metadata is not None:
        run.metadata_json = {**(run.metadata_json or {}), **payload.metadata}
    db.commit()
    db.refresh(run)
    return run_to_schema(run)


@v1_router.get("/runs", response_model=list[RunOut] | PageOut)
def list_runs(
    project_id: str = "default",
    status: str | None = None,
    agent: str | None = None,
    risk_label: str | None = None,
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[RunOut] | PageOut:
    authorize_project_access(auth, project_id)
    offset = int(cursor or 0)
    query = db.query(Run).filter(Run.project_id == project_id)
    if status:
        query = query.filter(Run.status == status)
    if agent:
        query = query.filter(Run.agent_id.ilike(f"%{agent}%"))
    if risk_label:
        candidates = query.order_by(Run.created_at.desc()).all()
        risk_label_lower = risk_label.lower()
        rows = [run for run in candidates if any(risk_label_lower in str(label).lower() for label in (run.risk_labels or []))][offset : offset + limit + 1]
    else:
        rows = query.order_by(Run.created_at.desc()).offset(offset).limit(limit + 1).all()
    has_more = len(rows) > limit
    items = [run_to_schema(run) for run in rows[:limit]]
    return page(items, limit, offset, has_more) if page_mode == "envelope" else items


@v1_router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str, request: Request, db: Session = Depends(get_db)) -> RunOut:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    authorize_project_access(get_auth_context(request), run.project_id, conceal=True)
    return run_to_schema(run)


@v1_router.get("/runs/{run_id}/events", response_model=list[TraceEventOut])
def get_run_events(run_id: str, request: Request, db: Session = Depends(get_db)) -> list[TraceEventOut]:
    run, project_id = project_for_resource(db, Run, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    authorize_project_access(get_auth_context(request), str(project_id), conceal=True)
    events = db.query(TraceEvent).filter(TraceEvent.run_id == run_id).order_by(TraceEvent.created_at.asc()).all()
    return [event_out(event) for event in events]


@v1_router.get("/runs/{run_id}/dag", response_model=RunDag)
def get_run_dag(run_id: str, request: Request, db: Session = Depends(get_db)) -> RunDag:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    authorize_project_access(get_auth_context(request), run.project_id, conceal=True)
    events = db.query(TraceEvent).filter(TraceEvent.run_id == run_id).order_by(TraceEvent.created_at.asc()).all()
    return build_dag(run, events)


@v1_router.post("/events", response_model=list[TraceEventOut])
def create_events(payload: EventsIn, request: Request, db: Session = Depends(get_db)) -> list[TraceEventOut]:
    records: list[TraceEvent] = []
    auth = get_auth_context(request)
    for event in payload.events:
        authorize_project_access(auth, event.project_id)
        run = db.get(Run, event.run_id)
        if not run:
            raise HTTPException(404, f"Run not found: {event.run_id}")
        authorize_project_access(auth, run.project_id, conceal=True)
        input_ref = event.input_ref or persist_content(db, event.project_id, event.input)
        output_ref = event.output_ref or persist_content(db, event.project_id, event.output)
        record = TraceEvent(
            id=event.event_id or new_id("evt"),
            run_id=event.run_id,
            project_id=event.project_id,
            trace_id=event.trace_id or run.trace_id,
            span_id=event.span_id or new_id("span"),
            parent_span_id=event.parent_span_id,
            event_type=event.event_type,
            status=event.status,
            actor=event.actor.model_dump(exclude_none=True),
            input_ref=input_ref,
            output_ref=output_ref,
            metadata_json=event.metadata,
            risk_score=event.risk.score,
            risk_labels=event.risk.labels,
            started_at=event.started_at,
            ended_at=event.ended_at,
        )
        db.add(record)
        records.append(record)
        if event.risk.labels:
            db.add(RiskEvent(id=new_id("risk"), project_id=event.project_id, run_id=event.run_id, event_id=record.id, risk_type=event.risk.labels[0], severity="high" if event.risk.score >= 0.7 else "medium", score=event.risk.score, labels=event.risk.labels, evidence=[], description=f"Risk labels reported by event {record.id}."))
    db.commit()
    return [event_out(record) for record in records]


@v1_router.get("/content/{content_id}", response_model=ContentOut)
def get_content(content_id: str, request: Request, db: Session = Depends(get_db)) -> ContentOut:
    content = db.get(ContentObject, content_id)
    if not content:
        raise HTTPException(404, "Content not found")
    authorize_project_access(get_auth_context(request), content.project_id, conceal=True)
    return ContentOut(id=content.id, content_hash=content.content_hash, summary=content.summary, redacted_text=content.redacted_text, labels=content.labels or [])
