from fastapi import APIRouter

from agentops_guard.backend.api import routes_admin, routes_control_plane, routes_eval, routes_gateway_registry, routes_jobs, routes_observability, routes_policy, routes_replay, routes_risks, routes_runs


router = APIRouter(prefix="/v1")
ops_router = APIRouter()

ops_router.include_router(routes_observability.router)
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
):
    router.include_router(module.v1_router)
