from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import risk_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import RiskEvent
from agentops_guard.backend.schemas import PageOut, RiskEventOut


v1_router = APIRouter()


@v1_router.get("/risks", response_model=list[RiskEventOut] | PageOut)
def list_risks(project_id: str = "default", severity: str | None = None, limit: int = Query(default=50, le=200), cursor: str | None = None, page_mode: str | None = None, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[RiskEventOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(RiskEvent).filter(RiskEvent.project_id == project_id)
    if severity:
        query = query.filter(RiskEvent.severity == severity)
    risks = query.order_by(RiskEvent.created_at.desc()).offset(offset).limit(limit + 1).all()
    has_more = len(risks) > limit
    items = [risk_out(risk) for risk in risks[:limit]]
    return page(items, limit, offset, has_more) if page_mode == "envelope" else items


@v1_router.get("/risks/{risk_id}", response_model=RiskEventOut)
def get_risk(risk_id: str, request: Request, db: Session = Depends(get_db)) -> RiskEventOut:
    risk = db.get(RiskEvent, risk_id)
    if not risk:
        raise HTTPException(404, "Risk event not found")
    authorize_project_access(get_auth_context(request), risk.project_id, conceal=True, db=db)
    return risk_out(risk)
