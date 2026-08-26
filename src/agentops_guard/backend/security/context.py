from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuthContext:
    kind: str
    project_id: str | None = None
    organization_id: str | None = None
    membership_id: str | None = None
    active_role: str | None = None
    memberships: list[dict[str, str]] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    key_id: str | None = None
    actor_id: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    user_display_name: str | None = None

    @property
    def is_operator(self) -> bool:
        return self.kind == "operator"

    @property
    def is_project_key(self) -> bool:
        return self.kind == "api_key"

    @property
    def is_session_user(self) -> bool:
        return self.kind == "session_user"


_current_auth: ContextVar[AuthContext | None] = ContextVar("agentops_auth_context", default=None)


def current_auth_context() -> AuthContext | None:
    return _current_auth.get()


def set_auth_context(context: AuthContext) -> None:
    _current_auth.set(context)


def clear_auth_context() -> None:
    _current_auth.set(None)
