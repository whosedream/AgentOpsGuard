from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import authorize_project_access, require_api_key, require_scope
from agentops_guard.backend.database import get_db
from agentops_guard.backend.security.context import AuthContext


@dataclass(frozen=True)
class GatewayIdentity:
    project_id: str
    auth_kind: str
    actor_id: str
    agent_id: str | None
    role: str | None

    @property
    def policy_actor(self) -> dict[str, str]:
        actor = {"auth_kind": self.auth_kind, "subject_id": self.actor_id}
        if self.agent_id is not None:
            actor["agent_id"] = self.agent_id
        if self.role is not None:
            actor["role"] = self.role
        return actor

    @property
    def audit_actor_type(self) -> str:
        if self.agent_id is not None:
            return "agent"
        if self.auth_kind == "session_user":
            return "user"
        return self.auth_kind


def require_gateway_identity(
    project_id: str | None = None,
    auth: AuthContext = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> GatewayIdentity:
    if auth.is_project_key and project_id is not None:
        authorize_project_access(auth, project_id, db=db)
    resolved_project_id = auth.project_id if auth.is_project_key else project_id or auth.project_id
    if resolved_project_id is None:
        resolved_project_id = "default"
    authorize_project_access(auth, resolved_project_id, db=db)
    return GatewayIdentity(
        project_id=resolved_project_id,
        auth_kind=auth.kind,
        actor_id=auth.actor_id or auth.kind,
        agent_id=auth.agent_id,
        role=auth.active_role,
    )


def require_gateway_read(
    identity: GatewayIdentity = Depends(require_gateway_identity),
    _auth: AuthContext = Depends(require_scope("mcp:read")),
) -> GatewayIdentity:
    return identity


def require_gateway_invoke(
    identity: GatewayIdentity = Depends(require_gateway_identity),
    _auth: AuthContext = Depends(require_scope("mcp:invoke")),
) -> GatewayIdentity:
    return identity
