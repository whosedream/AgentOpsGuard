from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import AuthContext, authorize_project_access, get_auth_context, require_scope
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import api_key_out, audit_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ApiKey, AuditLog
from agentops_guard.backend.schemas import ApiKeyCreate, ApiKeyCreateOut, ApiKeyOut, AuditLogOut, AuthContextOut, DeleteResponse, PageOut
from agentops_guard.backend.services.api_keys import create_api_key
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.projects import ensure_project


v1_router = APIRouter()


@v1_router.post("/api-keys", response_model=ApiKeyCreateOut, dependencies=[Depends(require_scope("api_keys:*"))])
def create_key(payload: ApiKeyCreate, request: Request, db: Session = Depends(get_db)) -> ApiKeyCreateOut:
    authorize_project_access(get_auth_context(request), payload.project_id)
    ensure_project(db, payload.project_id)
    row, token = create_api_key(db, payload.project_id, payload.name, payload.scopes, payload.expires_at)
    record_audit(db, project_id=payload.project_id, action="api_key.create", resource_type="api_key", resource_id=row.id, after={"name": row.name, "scopes": row.scopes})
    db.commit()
    db.refresh(row)
    return ApiKeyCreateOut(**api_key_out(row).model_dump(), token=token)


@v1_router.get("/api-keys", response_model=list[ApiKeyOut] | PageOut, dependencies=[Depends(require_scope("api_keys:*"))])
def list_keys(project_id: str = "default", limit: int = Query(default=50, le=200), cursor: str | None = None, page_mode: str | None = None, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[ApiKeyOut] | PageOut:
    authorize_project_access(auth, project_id)
    offset = int(cursor or 0)
    rows = db.query(ApiKey).filter(ApiKey.project_id == project_id).order_by(ApiKey.created_at.desc()).offset(offset).limit(limit).all()
    items = [api_key_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.delete("/api-keys/{key_id}", response_model=DeleteResponse, dependencies=[Depends(require_scope("api_keys:*"))])
def revoke_key(key_id: str, request: Request, db: Session = Depends(get_db)) -> DeleteResponse:
    row = db.get(ApiKey, key_id)
    if not row:
        raise HTTPException(404, "API key not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True)
    row.revoked_at = datetime.now(UTC)
    record_audit(db, project_id=row.project_id, action="api_key.revoke", resource_type="api_key", resource_id=row.id, before={"revoked_at": None}, after={"revoked_at": row.revoked_at.isoformat()})
    db.commit()
    return DeleteResponse(status="deleted", id=key_id)


@v1_router.get("/audit-logs", response_model=list[AuditLogOut] | PageOut, dependencies=[Depends(require_scope("audit:read"))])
def list_audit_logs(project_id: str = "default", limit: int = Query(default=50, le=200), cursor: str | None = None, page_mode: str | None = None, auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> list[AuditLogOut] | PageOut:
    authorize_project_access(auth, project_id)
    offset = int(cursor or 0)
    rows = db.query(AuditLog).filter(AuditLog.project_id == project_id).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    items = [audit_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get("/auth/context", response_model=AuthContextOut)
def auth_context(auth: AuthContext = Depends(get_auth_context)) -> AuthContextOut:
    capabilities = sorted(set(auth.scopes if auth.is_project_key else ["admin:*", "operator:*"]))
    return AuthContextOut(
        kind=auth.kind,
        project_id=auth.project_id,
        scopes=auth.scopes,
        capabilities=capabilities,
        is_operator=auth.is_operator,
    )
