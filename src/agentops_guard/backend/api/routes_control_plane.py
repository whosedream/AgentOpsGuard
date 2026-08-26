import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_organization_access, authorize_project_access, get_auth_context, require_scope
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ApprovalRequest, PolicyPack, Project, RunSuppression, ScanRule
from agentops_guard.backend.schemas import (
    ApprovalRequestCreate,
    ApprovalRequestOut,
    ApprovalReview,
    ControlPlaneStatusOut,
    DeleteResponse,
    PageOut,
    PolicyPackCreate,
    PolicyPackOut,
    PolicyPackUpdate,
    PolicyPackVersionCreate,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    RunSuppressionCreate,
    RunSuppressionOut,
    RunSuppressionUpdate,
    ScanRuleCreate,
    ScanRuleOut,
    ScanRuleUpdate,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.control_plane import (
    approval_out,
    control_plane_status,
    create_approval_request,
    create_policy_pack,
    create_policy_pack_version,
    create_project_config,
    create_run_suppression,
    create_scan_rule,
    policy_pack_out,
    project_out,
    review_approval_request,
    scan_rule_out,
    suppression_out,
    update_policy_pack,
    update_project_config,
    update_run_suppression,
    update_scan_rule,
)
from agentops_guard.backend.services.projects import ensure_project


v1_router = APIRouter()


def _page(items: list[object], limit: int, offset: int) -> PageOut:
    next_cursor = str(offset + limit) if len(items) == limit else None
    return PageOut(items=items, next_cursor=next_cursor)


@v1_router.get(
    "/control-plane/status",
    response_model=ControlPlaneStatusOut,
    dependencies=[Depends(require_scope("control:read"))],
)
def get_control_plane_status(project_id: str = "default", auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> ControlPlaneStatusOut:
    authorize_project_access(auth, project_id, db=db)
    return control_plane_status(db, project_id)


@v1_router.post(
    "/projects",
    response_model=ProjectOut,
    dependencies=[Depends(require_scope("control:admin"))],
)
def create_project(payload: ProjectCreate, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> ProjectOut:
    if auth.is_session_user and not payload.organization_id:
        payload = payload.model_copy(update={"organization_id": auth.organization_id})
    if auth.is_session_user and payload.organization_id:
        authorize_organization_access(auth, payload.organization_id)
    try:
        result = create_project_config(db, payload)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return result


@v1_router.get(
    "/projects",
    response_model=list[ProjectOut] | PageOut,
    dependencies=[Depends(require_scope("control:read"))],
)
def list_projects(
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[ProjectOut] | PageOut:
    if auth.is_project_key:
        raise HTTPException(403, "Project listing is not available for project API keys")
    offset = int(cursor or 0)
    query = db.query(Project)
    if not auth.is_operator and auth.organization_id:
        query = query.filter(Project.organization_id == auth.organization_id)
    rows = query.order_by(Project.created_at.desc()).offset(offset).limit(limit).all()
    items = [project_out(row) for row in rows]
    return _page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get(
    "/projects/{project_id}",
    response_model=ProjectOut,
    dependencies=[Depends(require_scope("control:read"))],
)
def get_project(project_id: str, request: Request, db: Session = Depends(get_db)) -> ProjectOut:
    authorize_project_access(get_auth_context(request), project_id, conceal=True, db=db)
    ensure_project(db, project_id)
    row = db.get(Project, project_id)
    if row is None:
        raise HTTPException(404, "Project not found")
    db.commit()
    return project_out(row)


@v1_router.patch(
    "/projects/{project_id}",
    response_model=ProjectOut,
    dependencies=[Depends(require_scope("control:admin"))],
)
def update_project(project_id: str, payload: ProjectUpdate, request: Request, db: Session = Depends(get_db)) -> ProjectOut:
    authorize_project_access(get_auth_context(request), project_id, conceal=True, db=db)
    try:
        result = update_project_config(db, project_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return result


@v1_router.post(
    "/approvals",
    response_model=ApprovalRequestOut,
    dependencies=[Depends(require_scope("approvals:write"))],
)
def create_approval(payload: ApprovalRequestCreate, request: Request, db: Session = Depends(get_db)) -> ApprovalRequestOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    result = create_approval_request(db, payload)
    db.commit()
    return result


@v1_router.get(
    "/approvals",
    response_model=list[ApprovalRequestOut] | PageOut,
    dependencies=[Depends(require_scope("approvals:read"))],
)
def list_approvals(
    project_id: str = "default",
    status: str | None = None,
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[ApprovalRequestOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(ApprovalRequest).filter(ApprovalRequest.project_id == project_id)
    if status:
        query = query.filter(ApprovalRequest.status == status)
    rows = query.order_by(ApprovalRequest.created_at.desc()).offset(offset).limit(limit).all()
    items = [approval_out(row) for row in rows]
    return _page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get(
    "/approvals/{approval_id}",
    response_model=ApprovalRequestOut,
    dependencies=[Depends(require_scope("approvals:read"))],
)
def get_approval(approval_id: str, request: Request, db: Session = Depends(get_db)) -> ApprovalRequestOut:
    row = db.get(ApprovalRequest, approval_id)
    if row is None:
        raise HTTPException(404, "Approval request not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    return approval_out(row)


@v1_router.post(
    "/approvals/{approval_id}/review",
    response_model=ApprovalRequestOut,
    dependencies=[Depends(require_scope("approvals:write"))],
)
def review_approval(approval_id: str, payload: ApprovalReview, request: Request, db: Session = Depends(get_db)) -> ApprovalRequestOut:
    row = db.get(ApprovalRequest, approval_id)
    if row is None:
        raise HTTPException(404, "Approval request not found")
    try:
        authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
        result = review_approval_request(db, approval_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return result


@v1_router.post(
    "/policy-packs",
    response_model=PolicyPackOut,
    dependencies=[Depends(require_scope("policies:admin"))],
)
def create_pack(payload: PolicyPackCreate, request: Request, db: Session = Depends(get_db)) -> PolicyPackOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    result = create_policy_pack(db, payload)
    db.commit()
    return result


@v1_router.get(
    "/policy-packs",
    response_model=list[PolicyPackOut] | PageOut,
    dependencies=[Depends(require_scope("policies:read"))],
)
def list_policy_packs(
    project_id: str = "default",
    status: str | None = None,
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[PolicyPackOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(PolicyPack).filter(PolicyPack.project_id == project_id)
    if status:
        query = query.filter(PolicyPack.status == status)
    rows = query.order_by(PolicyPack.created_at.desc()).offset(offset).limit(limit).all()
    items = [policy_pack_out(row) for row in rows]
    return _page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.patch(
    "/policy-packs/{pack_id}",
    response_model=PolicyPackOut,
    dependencies=[Depends(require_scope("policies:admin"))],
)
def update_pack(pack_id: str, payload: PolicyPackUpdate, request: Request, db: Session = Depends(get_db)) -> PolicyPackOut:
    row = db.get(PolicyPack, pack_id)
    if row is None:
        raise HTTPException(404, "Policy pack not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    try:
        result = update_policy_pack(db, pack_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return result


@v1_router.post(
    "/policy-packs/{pack_id}/versions",
    response_model=PolicyPackOut,
    dependencies=[Depends(require_scope("policies:admin"))],
)
def create_pack_version(pack_id: str, payload: PolicyPackVersionCreate, request: Request, db: Session = Depends(get_db)) -> PolicyPackOut:
    row = db.get(PolicyPack, pack_id)
    if row is None:
        raise HTTPException(404, "Policy pack not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    try:
        result = create_policy_pack_version(db, pack_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return result


@v1_router.delete(
    "/policy-packs/{pack_id}",
    response_model=DeleteResponse,
    dependencies=[Depends(require_scope("policies:admin"))],
)
def delete_pack(pack_id: str, request: Request, db: Session = Depends(get_db)) -> DeleteResponse:
    row = db.get(PolicyPack, pack_id)
    if row is None:
        raise HTTPException(404, "Policy pack not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    record_audit(db, project_id=row.project_id, action="policy_pack.delete", resource_type="policy_pack", resource_id=pack_id)
    db.delete(row)
    db.commit()
    return DeleteResponse(status="deleted", id=pack_id)


@v1_router.post(
    "/scanner/rules",
    response_model=ScanRuleOut,
    dependencies=[Depends(require_scope("scanner:admin"))],
)
def create_rule(payload: ScanRuleCreate, request: Request, db: Session = Depends(get_db)) -> ScanRuleOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    try:
        result = create_scan_rule(db, payload)
    except re.error as exc:
        raise HTTPException(422, f"Invalid scan rule regex: {exc}") from exc
    db.commit()
    return result


@v1_router.get(
    "/scanner/rules",
    response_model=list[ScanRuleOut] | PageOut,
    dependencies=[Depends(require_scope("scanner:read"))],
)
def list_scan_rules(
    project_id: str = "default",
    status: str | None = None,
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[ScanRuleOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    query = db.query(ScanRule).filter(ScanRule.project_id == project_id)
    if status:
        query = query.filter(ScanRule.status == status)
    rows = query.order_by(ScanRule.created_at.desc()).offset(offset).limit(limit).all()
    items = [scan_rule_out(row) for row in rows]
    return _page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.patch(
    "/scanner/rules/{rule_id}",
    response_model=ScanRuleOut,
    dependencies=[Depends(require_scope("scanner:admin"))],
)
def update_rule(rule_id: str, payload: ScanRuleUpdate, request: Request, db: Session = Depends(get_db)) -> ScanRuleOut:
    row = db.get(ScanRule, rule_id)
    if row is None:
        raise HTTPException(404, "Scan rule not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    try:
        result = update_scan_rule(db, rule_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    except re.error as exc:
        raise HTTPException(422, f"Invalid scan rule regex: {exc}") from exc
    db.commit()
    return result


@v1_router.delete(
    "/scanner/rules/{rule_id}",
    response_model=DeleteResponse,
    dependencies=[Depends(require_scope("scanner:admin"))],
)
def delete_rule(rule_id: str, request: Request, db: Session = Depends(get_db)) -> DeleteResponse:
    row = db.get(ScanRule, rule_id)
    if row is None:
        raise HTTPException(404, "Scan rule not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    record_audit(db, project_id=row.project_id, action="scan_rule.delete", resource_type="scan_rule", resource_id=rule_id)
    db.delete(row)
    db.commit()
    return DeleteResponse(status="deleted", id=rule_id)


@v1_router.post(
    "/runs/{run_id}/suppressions",
    response_model=RunSuppressionOut,
    dependencies=[Depends(require_scope("runs:admin"))],
)
def suppress_run(run_id: str, payload: RunSuppressionCreate, request: Request, db: Session = Depends(get_db)) -> RunSuppressionOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    try:
        result = create_run_suppression(db, run_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return result


@v1_router.get(
    "/runs/{run_id}/suppressions",
    response_model=list[RunSuppressionOut],
    dependencies=[Depends(require_scope("runs:read"))],
)
def list_run_suppressions(run_id: str, request: Request, db: Session = Depends(get_db)) -> list[RunSuppressionOut]:
    rows = db.query(RunSuppression).filter(RunSuppression.run_id == run_id).order_by(RunSuppression.created_at.desc()).all()
    if rows:
        authorize_project_access(get_auth_context(request), rows[0].project_id, conceal=True, db=db)
    return [suppression_out(row) for row in rows]


@v1_router.patch(
    "/suppressions/{suppression_id}",
    response_model=RunSuppressionOut,
    dependencies=[Depends(require_scope("runs:admin"))],
)
def update_suppression(
    suppression_id: str,
    payload: RunSuppressionUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> RunSuppressionOut:
    row = db.get(RunSuppression, suppression_id)
    if row is None:
        raise HTTPException(404, "Run suppression not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    try:
        result = update_run_suppression(db, suppression_id, payload)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return result
