from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from fastapi.params import Cookie as CookieParam
from fastapi.params import Header as HeaderParam
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ApiKey, Membership, Project, Session as AuthSession, User
from agentops_guard.backend.security.context import AuthContext, current_auth_context, set_auth_context
from agentops_guard.backend.services.api_keys import authenticate_api_key, has_scope
from agentops_guard.backend.services.identity import authenticate_session, role_capabilities


def _extract_token(authorization: str | None, x_agentops_api_key: str | None) -> str | None:
    auth_header = None if isinstance(authorization, HeaderParam) else authorization
    token = None if isinstance(x_agentops_api_key, HeaderParam) else x_agentops_api_key
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
    return token


def require_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agentops_api_key: str | None = Header(default=None),
    session_cookie: str | None = Cookie(default=None, alias="agentops_session"),
    db: Session = Depends(get_db),
) -> AuthContext:
    if isinstance(getattr(request.state, "auth_context", None), AuthContext):
        context = request.state.auth_context
        set_auth_context(context)
        return context

    settings = get_settings()
    normalized_cookie = None if isinstance(session_cookie, CookieParam) else session_cookie
    db_session = db if isinstance(db, Session) else None
    token = _extract_token(authorization, x_agentops_api_key)
    if token == settings.effective_operator_api_key:
        context = AuthContext(
            kind="operator",
            scopes=["admin:*"],
            capabilities=["admin:*", "operator:*"],
            actor_id="operator",
        )
        _store_auth_context(request, context)
        return context

    if normalized_cookie and db_session is not None:
        session_row = authenticate_session(db_session, normalized_cookie)
        if session_row:
            context = _session_auth_context(db_session, session_row)
            _store_auth_context(request, context)
            return context

    if token and db_session is not None:
        row = authenticate_api_key(db_session, token)
        if row:
            db_session.commit()
            project = db_session.get(Project, row.project_id)
            context = AuthContext(
                kind="api_key",
                project_id=row.project_id,
                organization_id=project.organization_id if project else None,
                scopes=row.scopes or [],
                capabilities=row.scopes or [],
                key_id=row.id,
                actor_id=row.id,
            )
            _store_auth_context(request, context)
            return context

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def require_scope(required_scope: str):
    def dependency(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
        if auth.is_operator:
            return auth
        if auth.is_session_user:
            if required_scope in auth.capabilities:
                return auth
            prefix_capability = f"{required_scope.split(':', 1)[0]}:*"
            if prefix_capability in auth.capabilities or "admin:*" in auth.capabilities:
                return auth
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Membership capability denied")
        row = ApiKey(id=auth.key_id or "", project_id=auth.project_id or "", name="scoped", key_hash="", scopes=auth.scopes)
        if not has_scope(row, required_scope):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key scope denied")
        return auth

    return dependency


def require_operator(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
    if not auth.is_operator:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator API key required")
    return auth


def require_session_user(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
    if not auth.is_session_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session login required")
    return auth


def require_membership_capability(required_capability: str):
    def dependency(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
        if auth.is_operator:
            return auth
        if not auth.is_session_user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session login required")
        if required_capability in auth.capabilities:
            return auth
        prefix_capability = f"{required_capability.split(':', 1)[0]}:*"
        if prefix_capability in auth.capabilities or "admin:*" in auth.capabilities:
            return auth
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Membership capability denied")

    return dependency


def authorize_project_access(auth: AuthContext, project_id: str, *, conceal: bool = False, db: Session | None = None) -> None:
    if auth.is_operator:
        return
    if auth.is_project_key:
        if auth.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND if conceal else status.HTTP_403_FORBIDDEN,
                detail="Resource not found" if conceal else "Project access denied",
            )
        return
    if not auth.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organization access denied")
    if db is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="DB session required for project authorization")
    project = db.get(Project, project_id)
    if project is None or project.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if conceal else status.HTTP_403_FORBIDDEN,
            detail="Resource not found" if conceal else "Project access denied",
        )


def authorize_organization_access(auth: AuthContext, organization_id: str, *, conceal: bool = False) -> None:
    if auth.is_operator:
        return
    if auth.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if conceal else status.HTTP_403_FORBIDDEN,
            detail="Resource not found" if conceal else "Organization access denied",
        )


def authorize_project_membership_access(auth: AuthContext, project: Project | None, *, conceal: bool = False) -> None:
    if auth.is_operator:
        return
    if project is None or auth.organization_id != project.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if conceal else status.HTTP_403_FORBIDDEN,
            detail="Resource not found" if conceal else "Project access denied",
        )


def get_auth_context(request: Request) -> AuthContext:
    context = getattr(request.state, "auth_context", None)
    if isinstance(context, AuthContext):
        return context
    fallback = current_auth_context()
    if fallback is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication context is unavailable")
    return fallback


def _store_auth_context(request: Request, context: AuthContext) -> None:
    set_auth_context(context)
    request.state.auth_context = context


def _session_auth_context(db: Session, session_row: AuthSession) -> AuthContext:
    membership = db.get(Membership, session_row.membership_id)
    user = db.get(User, membership.user_id) if membership else None
    memberships = (
        db.query(Membership)
        .filter(Membership.user_id == session_row.user_id, Membership.status == "active")
        .all()
    )
    project = (
        db.query(Project)
        .filter(Project.organization_id == session_row.organization_id)
        .order_by(Project.created_at.asc())
        .first()
    )
    active_role = membership.role if membership else None
    capabilities = role_capabilities(active_role or "")
    return AuthContext(
        kind="session_user",
        project_id=project.id if project else None,
        organization_id=session_row.organization_id,
        membership_id=session_row.membership_id,
        active_role=active_role,
        memberships=[
            {
                "id": item.id,
                "organization_id": item.organization_id,
                "role": item.role,
                "status": item.status,
            }
            for item in memberships
        ],
        scopes=[],
        capabilities=capabilities,
        actor_id=session_row.user_id,
        user_id=session_row.user_id,
        user_email=user.email if user else None,
        user_display_name=user.display_name if user else None,
    )
