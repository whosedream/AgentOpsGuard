from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentops_guard.backend.auth import require_api_key
from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import init_db
from agentops_guard.backend.observability import RequestContextMiddleware
from agentops_guard.backend.routes import ops_router, public_router, router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AgentOps Guard API",
        version="0.1.0",
        description="Self-hosted Agent tracing, evaluation, and security gateway for MCP + Python agents.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials="*" not in settings.cors_allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestContextMiddleware)
    app.include_router(ops_router)
    app.include_router(public_router)
    app.include_router(router, dependencies=[Depends(require_api_key)])
    return app


app = create_app()
