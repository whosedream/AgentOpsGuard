from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import PolicyDecision
from agentops_guard.backend.schemas import PolicyContext, PolicyDecisionOut, ScanRequest, ScanResponse
from agentops_guard.backend.services.policy import evaluate_policy, persist_policy_decision
from agentops_guard.backend.services.opa import check_opa_health
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.scanner import scan_content


v1_router = APIRouter()


@v1_router.post("/policies/evaluate", response_model=PolicyDecisionOut)
def evaluate(payload: PolicyContext, request: Request, db: Session = Depends(get_db)) -> PolicyDecisionOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    ensure_project(db, payload.project_id)
    decision = persist_policy_decision(db, evaluate_policy(payload, db), payload)
    db.commit()
    return decision


@v1_router.get("/policies/decisions", response_model=list[PolicyDecisionOut])
def list_policy_decisions(project_id: str = "default", limit: int = Query(default=50, le=200), auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[PolicyDecisionOut]:
    authorize_project_access(auth, project_id, db=db)
    rows = db.query(PolicyDecision).filter(PolicyDecision.project_id == project_id).order_by(PolicyDecision.created_at.desc()).limit(limit).all()
    return [PolicyDecisionOut(id=row.id, action=row.action, reason_code=row.reason_code, severity=row.severity, matched_policy=row.matched_policy, remediation=row.remediation, context=row.context or {}) for row in rows]


@v1_router.post("/policies/reload")
def reload_policies() -> dict[str, str]:
    check_opa_health()
    return {
        "status": "ok",
        "message": "Policy provider is healthy; file and bundle updates are managed by the deployment.",
    }


@v1_router.post("/scanner/scan", response_model=ScanResponse)
def scan(payload: ScanRequest, request: Request, db: Session = Depends(get_db)) -> ScanResponse:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    ensure_project(db, payload.project_id)
    response = scan_content(payload, db)
    db.commit()
    return response
