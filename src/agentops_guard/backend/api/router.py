from fastapi import APIRouter

from agentops_guard.backend.api import routes_admin, routes_control_plane, routes_credentials, routes_eval, routes_gateway_registry, routes_jobs, routes_observability, routes_policy, routes_replay, routes_risks, routes_runs


router = APIRouter(prefix="/v1")
public_router = APIRouter(prefix="/v1")
ops_router = APIRouter()

ops_router.include_router(routes_observability.router)
public_router.include_router(routes_admin.public_v1_router)
for module in (
    routes_observability,
    routes_runs,
    routes_policy,
    routes_risks,
    routes_replay,
    routes_eval,
    routes_gateway_registry,
    routes_control_plane,
    routes_admin,
    routes_jobs,
    routes_credentials,
):
    router.include_router(module.v1_router)
