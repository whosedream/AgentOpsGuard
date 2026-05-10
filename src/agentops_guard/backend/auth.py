from contextvars import ContextVar
from dataclasses import dataclass, field

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.params import Header as HeaderParam
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ApiKey
from agentops_guard.backend.services.api_keys import authenticate_api_key, has_scope

_current_auth: ContextVar["AuthContext | None"] = ContextVar("agentops_auth_context", default=None)


@dataclass(frozen=True)
class AuthContext:
    kind: str
    project_id: str | None = None
    scopes: list[str] = field(default_factory=list)
    key_id: str | None = None
    actor_id: str | None = None

    @property
    def is_operator(self) -> bool:
        return self.kind == "operator"

    @property
    def is_project_key(self) -> bool:
        return self.kind == "project_key"


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
    db: Session = Depends(get_db),
) -> AuthContext:
    if isinstance(getattr(request.state, "auth_context", None), AuthContext):
        context = request.state.auth_context
        _current_auth.set(context)
        return context
    settings = get_settings()
    token = _extract_token(authorization, x_agentops_api_key)
    if token == settings.effective_operator_api_key:
        context = AuthContext(kind="operator", scopes=["admin:*"], actor_id="operator")
        _store_auth_context(request, context)
        return context
    if not isinstance(db, Session):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid AgentOps API key")
    if token:
        row = authenticate_api_key(db, token)
        if row:
            db.commit()
            context = AuthContext(
                kind="project_key",
                project_id=row.project_id,
                scopes=row.scopes or [],
                key_id=row.id,
                actor_id=row.id,
            )
            _store_auth_context(request, context)
            return context
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid AgentOps API key")


def require_scope(required_scope: str):
    def dependency(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
        if auth.is_operator:
            return auth
        row = ApiKey(id=auth.key_id or "", project_id=auth.project_id or "", name="scoped", key_hash="", scopes=auth.scopes)
        if not has_scope(row, required_scope):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="AgentOps API key scope denied")
        return auth

    return dependency


def require_operator(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
    if not auth.is_operator:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator API key required")
    return auth


def authorize_project_access(auth: AuthContext, project_id: str, *, conceal: bool = False) -> None:
    if auth.is_operator:
        return
    if auth.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if conceal else status.HTTP_403_FORBIDDEN,
            detail="Resource not found" if conceal else "Project access denied",
        )


def get_auth_context(request: Request) -> AuthContext:
    context = getattr(request.state, "auth_context", None)
    if isinstance(context, AuthContext):
        return context
    fallback = _current_auth.get()
    if fallback is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication context is unavailable")
    return fallback


def current_auth_context() -> AuthContext | None:
    return _current_auth.get()


def _store_auth_context(request: Request, context: AuthContext) -> None:
    _current_auth.set(context)
    request.state.auth_context = context
