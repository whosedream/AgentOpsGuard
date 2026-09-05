from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from agentops_guard.backend.security.context import clear_auth_context


class AuthContextLifecycleMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        clear_auth_context()
        try:
            return await call_next(request)
        finally:
            clear_auth_context()
