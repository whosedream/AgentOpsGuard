from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import PolicyDecision
from agentops_guard.backend.schemas import PolicyContext, PolicyDecisionOut, ScanRequest, ScanResponse
from agentops_guard.backend.services.policy import evaluate_policy, persist_policy_decision
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.scanner import scan_content


v1_router = APIRouter()


@v1_router.post("/policies/evaluate", response_model=PolicyDecisionOut)
def evaluate(payload: PolicyContext, db: Session = Depends(get_db)) -> PolicyDecisionOut:
    ensure_project(db, payload.project_id)
    decision = persist_policy_decision(db, evaluate_policy(payload, db), payload)
    db.commit()
    return decision


@v1_router.get("/policies/decisions", response_model=list[PolicyDecisionOut])
def list_policy_decisions(project_id: str = "default", limit: int = Query(default=50, le=200), db: Session = Depends(get_db)) -> list[PolicyDecisionOut]:
    rows = db.query(PolicyDecision).filter(PolicyDecision.project_id == project_id).order_by(PolicyDecision.created_at.desc()).limit(limit).all()
    return [PolicyDecisionOut(id=row.id, action=row.action, reason_code=row.reason_code, severity=row.severity, matched_policy=row.matched_policy, remediation=row.remediation, context=row.context or {}) for row in rows]


@v1_router.post("/policies/reload")
def reload_policies() -> dict[str, str]:
    return {"status": "ok", "message": "Built-in policy pack is active; OPA reload hook reserved for deployment."}


@v1_router.post("/scanner/scan", response_model=ScanResponse)
def scan(payload: ScanRequest, db: Session = Depends(get_db)) -> ScanResponse:
    ensure_project(db, payload.project_id)
    response = scan_content(payload, db)
    db.commit()
    return response
