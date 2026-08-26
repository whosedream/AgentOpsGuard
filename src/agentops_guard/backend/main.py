from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agentops_guard.backend.auth import require_api_key
from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import init_db
from agentops_guard.backend.observability import RequestContextMiddleware
from agentops_guard.backend.routes import ops_router, public_router, router
from agentops_guard.backend.services.credentials import CredentialVault
from agentops_guard.backend.telemetry import TelemetryMiddleware, configure_telemetry


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    encryption_key = settings.credential_encryption_key
    if settings.credential_store == "fernet" and encryption_key is not None:
        try:
            CredentialVault(encryption_key.get_secret_value())
        except ValueError:
            raise RuntimeError("Credential encryption key is invalid") from None
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_telemetry("agentops-guard-api")
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
    app.add_middleware(TelemetryMiddleware, component="api")

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request, exc):
        if request.url.path.startswith(("/v1/credentials/", "/v1/deepseek/")):
            return JSONResponse(
                status_code=422, content={"detail": "Invalid request"}
            )
        return await request_validation_exception_handler(request, exc)

    app.include_router(ops_router)
    app.include_router(public_router)
    app.include_router(router, dependencies=[Depends(require_api_key)])
    return app


app = create_app()
