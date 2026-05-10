from fastapi import Depends, Header, HTTPException, status
from fastapi.params import Header as HeaderParam
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ApiKey
from agentops_guard.backend.services.api_keys import authenticate_api_key, has_scope


def _extract_token(authorization: str | None, x_agentops_api_key: str | None) -> str | None:
    auth_header = None if isinstance(authorization, HeaderParam) else authorization
    token = None if isinstance(x_agentops_api_key, HeaderParam) else x_agentops_api_key
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
    return token


def require_api_key(
    authorization: str | None = Header(default=None),
    x_agentops_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> ApiKey | None:
    settings = get_settings()
    token = _extract_token(authorization, x_agentops_api_key)
    if token == settings.api_key:
        return None
    if not isinstance(db, Session):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid AgentOps API key")
    if token:
        row = authenticate_api_key(db, token)
        if row:
            db.commit()
            return row
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid AgentOps API key")


def require_scope(required_scope: str):
    def dependency(api_key: ApiKey | None = Depends(require_api_key)) -> ApiKey | None:
        if not has_scope(api_key, required_scope):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="AgentOps API key scope denied")
        return api_key

    return dependency
