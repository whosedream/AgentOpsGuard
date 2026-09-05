from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import (
    AuthContext,
    authorize_organization_access,
    authorize_project_access,
    get_auth_context,
    require_membership_capability,
    require_scope,
)
from agentops_guard.backend.api.pagination import page
from agentops_guard.backend.api.serializers import api_key_out, audit_out
from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import (
    ApiKey,
    AuditCheckpoint,
    AuditLog,
    Membership,
    Organization,
    User,
)
from agentops_guard.backend.schemas import (
    ApiKeyCreate,
    ApiKeyCreateOut,
    ApiKeyOut,
    AuditCheckpointIntegrityOut,
    AuditCheckpointOut,
    AuditIntegrityOut,
    AuditLogOut,
    AuthContextOut,
    AuthContextUserOut,
    DeleteResponse,
    DevLoginOut,
    DevLoginRequest,
    MembershipCreate,
    MembershipOut,
    MembershipSummaryOut,
    MembershipUpdate,
    OrganizationCreate,
    OrganizationOut,
    PageOut,
    UserOut,
)
from agentops_guard.backend.services.api_keys import create_api_key
from agentops_guard.backend.services.audit import record_audit, verify_audit_chain
from agentops_guard.backend.services.audit_checkpoints import (
    AuditCheckpointUnavailable,
    audit_checkpoint_payload,
    configured_audit_signer,
    create_audit_checkpoint,
    verify_audit_checkpoint,
)
from agentops_guard.backend.services.identity import (
    create_dev_session,
    create_membership,
    create_organization,
    create_session_record,
    revoke_session,
    update_membership,
)
from agentops_guard.backend.services.projects import ensure_project


public_v1_router = APIRouter()
v1_router = APIRouter()


@public_v1_router.post("/auth/dev-login", response_model=DevLoginOut)
def dev_login(
    payload: DevLoginRequest, response: Response, db: Session = Depends(get_db)
) -> DevLoginOut:
    from agentops_guard.backend.config import get_settings

    settings = get_settings()
    if settings.env not in {"dev", "test"}:
        raise HTTPException(403, "Development login is disabled")
    organization, user, membership, project = create_dev_session(
        db,
        email=payload.email,
        display_name=payload.display_name,
        role=payload.role,
        organization_id=payload.organization_id,
        organization_name=payload.organization_name,
    )
    session_row, session_token = create_session_record(
        db,
        user_id=user.id,
        organization_id=organization.id,
        membership_id=membership.id,
        provider="dev_stub",
    )
    response.set_cookie(
        key="agentops_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=settings.env == "prod",
        max_age=12 * 60 * 60,
    )
    record_audit(
        db,
        project_id=project.id,
        action="auth.dev_login",
        resource_type="session",
        resource_id=session_row.id,
        actor_type="session_user",
        actor_id=user.id,
        after={
            "organization_id": membership.organization_id,
            "membership_id": membership.id,
            "role": membership.role,
        },
    )
    db.commit()
    return DevLoginOut(
        session_id=session_row.id,
        user=UserOut(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            auth_provider=user.auth_provider,
            status=user.status,
            created_at=user.created_at,
        ),
        membership=_membership_out(db, membership),
        project_id=project.id if project else None,
    )


@public_v1_router.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, str]:
    session_id = request.cookies.get("agentops_session")
    if session_id:
        revoke_session(db, session_id)
        db.commit()
    response.delete_cookie("agentops_session")
    return {"status": "ok"}


@v1_router.post("/organizations", response_model=OrganizationOut)
def create_org(
    payload: OrganizationCreate,
    auth: AuthContext = Depends(require_scope("admin:*")),
    db: Session = Depends(get_db),
) -> OrganizationOut:
    if not auth.is_operator:
        raise HTTPException(403, "Operator API key required")
    organization, user, membership, project = create_organization(db, payload)
    record_audit(
        db,
        project_id=project.id if project else "bootstrap",
        action="organization.create",
        resource_type="organization",
        resource_id=organization.id,
        after={"slug": organization.slug, "name": organization.name},
        actor_type="operator",
        actor_id="operator",
    )
    db.commit()
    return OrganizationOut(
        id=organization.id,
        slug=organization.slug,
        name=organization.name,
        created_at=organization.created_at,
        initial_project_id=project.id if project else None,
    )


@v1_router.get("/organizations", response_model=list[OrganizationOut])
def list_organizations(
    auth: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)
) -> list[OrganizationOut]:
    if auth.is_operator:
        rows = db.query(Organization).order_by(Organization.created_at.asc()).all()
    elif auth.organization_id:
        rows = db.query(Organization).filter(Organization.id == auth.organization_id).all()
    else:
        raise HTTPException(403, "Organization access denied")
    return [
        OrganizationOut(
            id=row.id,
            slug=row.slug,
            name=row.name,
            created_at=row.created_at,
        )
        for row in rows
    ]


@v1_router.get("/organizations/{organization_id}", response_model=OrganizationOut)
def get_organization(
    organization_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> OrganizationOut:
    row = db.get(Organization, organization_id)
    if row is None:
        raise HTTPException(404, "Organization not found")
    authorize_organization_access(auth, organization_id, conceal=True)
    return OrganizationOut(
        id=row.id,
        slug=row.slug,
        name=row.name,
        created_at=row.created_at,
    )


@v1_router.post(
    "/organizations/{organization_id}/memberships",
    response_model=MembershipOut,
    dependencies=[Depends(require_membership_capability("organizations:write"))],
)
def create_org_membership(
    organization_id: str,
    payload: MembershipCreate,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> MembershipOut:
    authorize_organization_access(auth, organization_id, conceal=True)
    try:
        membership = create_membership(db, organization_id, payload)
    except ValueError as exc:
        raise HTTPException(422, "Membership request is invalid") from exc
    db.commit()
    return _membership_out(db, membership)


@v1_router.patch(
    "/memberships/{membership_id}",
    response_model=MembershipOut,
    dependencies=[Depends(require_membership_capability("organizations:write"))],
)
def patch_membership(
    membership_id: str,
    payload: MembershipUpdate,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> MembershipOut:
    row = db.get(Membership, membership_id)
    if row is None:
        raise HTTPException(404, "Membership not found")
    authorize_organization_access(auth, row.organization_id, conceal=True)
    updated = update_membership(db, membership_id, payload)
    db.commit()
    return _membership_out(db, updated)


@v1_router.post(
    "/api-keys", response_model=ApiKeyCreateOut, dependencies=[Depends(require_scope("api_keys:*"))]
)
def create_key(
    payload: ApiKeyCreate, request: Request, db: Session = Depends(get_db)
) -> ApiKeyCreateOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    project = ensure_project(db, payload.project_id)
    row, token = create_api_key(
        db,
        payload.project_id,
        payload.name,
        payload.scopes,
        payload.expires_at,
        payload.agent_id,
    )
    record_audit(
        db,
        project_id=payload.project_id,
        action="api_key.create",
        resource_type="api_key",
        resource_id=row.id,
        after={
            "name": row.name,
            "agent_id": row.agent_id,
            "scopes": row.scopes,
            "organization_id": project.organization_id,
        },
    )
    db.commit()
    db.refresh(row)
    return ApiKeyCreateOut(**api_key_out(row).model_dump(), token=token)


@v1_router.get(
    "/api-keys",
    response_model=list[ApiKeyOut] | PageOut,
    dependencies=[Depends(require_scope("api_keys:*"))],
)
def list_keys(
    project_id: str = "default",
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[ApiKeyOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    rows = (
        db.query(ApiKey)
        .filter(ApiKey.project_id == project_id)
        .order_by(ApiKey.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    items = [api_key_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.delete(
    "/api-keys/{key_id}",
    response_model=DeleteResponse,
    dependencies=[Depends(require_scope("api_keys:*"))],
)
def revoke_key(key_id: str, request: Request, db: Session = Depends(get_db)) -> DeleteResponse:
    row = db.get(ApiKey, key_id)
    if not row:
        raise HTTPException(404, "API key not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    row.revoked_at = datetime.now(UTC)
    record_audit(
        db,
        project_id=row.project_id,
        action="api_key.revoke",
        resource_type="api_key",
        resource_id=row.id,
        before={"revoked_at": None},
        after={"revoked_at": row.revoked_at.isoformat()},
    )
    db.commit()
    return DeleteResponse(status="deleted", id=key_id)


@v1_router.get(
    "/audit-logs",
    response_model=list[AuditLogOut] | PageOut,
    dependencies=[Depends(require_scope("audit:read"))],
)
def list_audit_logs(
    project_id: str = "default",
    limit: int = Query(default=50, le=200),
    cursor: str | None = None,
    page_mode: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[AuditLogOut] | PageOut:
    authorize_project_access(auth, project_id, db=db)
    offset = int(cursor or 0)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.project_id == project_id)
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    items = [audit_out(row) for row in rows]
    return page(items, limit, offset) if page_mode == "envelope" else items


@v1_router.get(
    "/audit-logs/integrity",
    response_model=AuditIntegrityOut,
    dependencies=[Depends(require_scope("audit:read"))],
)
def audit_log_integrity(
    project_id: str = "default",
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> AuditIntegrityOut:
    authorize_project_access(auth, project_id, db=db)
    result = verify_audit_chain(db, project_id)
    return AuditIntegrityOut(
        valid=result.valid,
        checked_entries=result.checked_entries,
        broken_entry_id=result.broken_entry_id,
    )


@v1_router.post(
    "/audit-logs/checkpoints",
    response_model=AuditCheckpointOut,
    dependencies=[Depends(require_scope("audit:write"))],
)
def issue_audit_checkpoint(
    project_id: str = "default",
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> AuditCheckpointOut:
    authorize_project_access(auth, project_id, db=db)
    try:
        row = create_audit_checkpoint(db, project_id=project_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except AuditCheckpointUnavailable as exc:
        raise HTTPException(503, "Audit checkpoint signer unavailable") from exc
    record_audit(
        db,
        project_id=project_id,
        action="audit.checkpoint_issued",
        resource_type="audit_checkpoint",
        resource_id=row.id,
        after={
            "entry_id": row.entry_id,
            "entry_hash": row.entry_hash,
            "checked_entries": row.checked_entries,
            "payload_digest": row.payload_digest,
            "key_name": row.key_name,
            "key_version": row.key_version,
        },
    )
    db.commit()
    return _audit_checkpoint_out(row)


@v1_router.get(
    "/audit-logs/checkpoints",
    response_model=list[AuditCheckpointOut],
    dependencies=[Depends(require_scope("audit:read"))],
)
def list_audit_checkpoints(
    project_id: str = "default",
    limit: int = Query(default=50, le=200),
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[AuditCheckpointOut]:
    authorize_project_access(auth, project_id, db=db)
    rows = (
        db.query(AuditCheckpoint)
        .filter(AuditCheckpoint.project_id == project_id)
        .order_by(AuditCheckpoint.issued_at.desc())
        .limit(limit)
        .all()
    )
    return [_audit_checkpoint_out(row) for row in rows]


@v1_router.get(
    "/audit-logs/checkpoints/{checkpoint_id}/integrity",
    response_model=AuditCheckpointIntegrityOut,
    dependencies=[Depends(require_scope("audit:read"))],
)
def audit_checkpoint_integrity(
    checkpoint_id: str,
    project_id: str = "default",
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> AuditCheckpointIntegrityOut:
    authorize_project_access(auth, project_id, db=db)
    row = db.get(AuditCheckpoint, checkpoint_id)
    if row is None or row.project_id != project_id:
        raise HTTPException(404, "Audit checkpoint not found")
    signer = None
    if get_settings().audit_checkpoint_backend == "openbao":
        signer = configured_audit_signer()
    try:
        result = verify_audit_checkpoint(db, row, signer=signer)
    except AuditCheckpointUnavailable as exc:
        raise HTTPException(503, "Audit checkpoint signer unavailable") from exc
    return AuditCheckpointIntegrityOut(
        valid=result.valid,
        signature_valid=result.signature_valid,
        chain_prefix_valid=result.chain_prefix_valid,
        key_origin_valid=result.key_origin_valid,
        reason=result.reason,
    )


def _audit_checkpoint_out(row: AuditCheckpoint) -> AuditCheckpointOut:
    payload = audit_checkpoint_payload(
        project_id=row.project_id,
        entry_id=row.entry_id,
        entry_hash=row.entry_hash,
        checked_entries=row.checked_entries,
        issued_at=row.issued_at,
    )
    return AuditCheckpointOut(
        id=row.id,
        project_id=row.project_id,
        entry_id=row.entry_id,
        entry_hash=row.entry_hash,
        checked_entries=row.checked_entries,
        payload_digest=row.payload_digest,
        signer=row.signer,
        key_name=row.key_name,
        key_version=row.key_version,
        signature=row.signature,
        public_key=row.public_key,
        issued_at=row.issued_at,
        payload=payload,
    )


@v1_router.get("/auth/context", response_model=AuthContextOut)
def auth_context(auth: AuthContext = Depends(get_auth_context)) -> AuthContextOut:
    return AuthContextOut(
        kind=auth.kind,
        user=AuthContextUserOut(
            id=auth.user_id or "",
            email=auth.user_email or "",
            display_name=auth.user_display_name or "",
        )
        if auth.user_id
        else None,
        organization_id=auth.organization_id,
        memberships=[
            MembershipSummaryOut(
                id=item["id"],
                organization_id=item["organization_id"],
                role=item["role"],
                status=item["status"],
            )
            for item in auth.memberships
        ],
        active_membership_id=auth.membership_id,
        active_role=auth.active_role,
        project_id=auth.project_id,
        scopes=auth.scopes,
        capabilities=sorted(set(auth.capabilities)),
        is_operator=auth.is_operator,
    )


def _membership_out(db: Session, membership: Membership) -> MembershipOut:
    user = db.get(User, membership.user_id)
    return MembershipOut(
        id=membership.id,
        organization_id=membership.organization_id,
        user_id=membership.user_id,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
        user=UserOut(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            auth_provider=user.auth_provider,
            status=user.status,
            created_at=user.created_at,
        ),
    )
