from fastapi import APIRouter, Depends, Response
from fastapi.responses import PlainTextResponse
from redis.exceptions import RedisError
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import (
    ApprovalRequest,
    BackgroundJob,
    EvalRun,
    EvalSuite,
    ExecutionRequest,
    McpServer,
    McpTool,
    OutboxEvent,
    PolicyDecision,
    PolicyPack,
    Project,
    ReplayRun,
    RiskEvent,
    Run,
    RunSuppression,
    ScanRule,
)
from agentops_guard.backend.observability import (
    APPROVALS_PENDING_GAUGE,
    JOBS_BY_STATUS_GAUGE,
    JOBS_GAUGE,
    MCP_SERVERS_GAUGE,
    MCP_TOOLS_GAUGE,
    POLICY_DECISIONS_GAUGE,
    POLICY_PACKS_GAUGE,
    RISKS_GAUGE,
    RUNS_GAUGE,
    SCAN_RULES_GAUGE,
    EXECUTIONS_BY_STATUS_GAUGE,
    OUTBOX_BY_STATUS_GAUGE,
    metrics_payload,
)
from agentops_guard.backend.schemas import (
    ComponentStatus,
    SystemConfig,
    SystemCounts,
    SystemStatusOut,
)
from agentops_guard.backend.services.jobs import redis_connection
from agentops_guard.backend.services.credentials import (
    CredentialStoreUnavailable,
    OpenBaoCredentialStore,
    configured_credential_store,
)
from agentops_guard.backend.services.migrations import migration_status
from agentops_guard.backend.services.opa import OpaUnavailable, check_opa_health
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.audit_checkpoints import (
    AuditCheckpointUnavailable,
    configured_audit_signer,
)


router = APIRouter()
v1_router = APIRouter()


@v1_router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(response: Response, db: Session = Depends(get_db)) -> dict[str, ComponentStatus]:
    settings = get_settings()
    database = ComponentStatus(status="ok")
    redis = ComponentStatus(status="ok")
    opa = ComponentStatus(status="disabled" if settings.opa_url is None else "ok")
    credential_store = ComponentStatus(
        status=(
            "disabled"
            if settings.credential_store == "fernet" and settings.credential_encryption_key is None
            else "ok"
        )
    )
    audit_checkpoint = ComponentStatus(
        status="disabled" if settings.audit_checkpoint_backend == "disabled" else "ok"
    )
    status_code = "ok"
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        status_code = "error"
        database = ComponentStatus(status="error", detail="Database unavailable")
    migration = (
        migration_status(db)
        if database.status == "ok"
        else ComponentStatus(status="error", detail="database unavailable")
    )
    if migration.status == "error":
        status_code = "error"
    try:
        redis_connection().ping()
    except RedisError:
        redis = ComponentStatus(
            status="degraded",
            detail="Redis unavailable; committed jobs remain in the database outbox",
        )
    try:
        check_opa_health()
    except OpaUnavailable:
        status_code = "error"
        opa = ComponentStatus(status="error", detail="OPA unavailable")
    if settings.credential_store == "openbao":
        try:
            store = configured_credential_store()
            assert isinstance(store, OpenBaoCredentialStore)
            store.check_health()
        except CredentialStoreUnavailable:
            status_code = "error"
            credential_store = ComponentStatus(status="error", detail="OpenBao unavailable")
    if settings.audit_checkpoint_backend == "openbao":
        try:
            configured_audit_signer().check_ready()
        except AuditCheckpointUnavailable:
            status_code = "error"
            audit_checkpoint = ComponentStatus(
                status="error", detail="OpenBao audit signing key unavailable"
            )
    if status_code != "ok":
        response.status_code = 503
    return {
        "status": ComponentStatus(status=status_code),
        "database": database,
        "redis": redis,
        "migration": migration,
        "opa": opa,
        "credential_store": credential_store,
        "audit_checkpoint": audit_checkpoint,
    }


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)) -> PlainTextResponse:
    RUNS_GAUGE.set(db.query(Run).count())
    RISKS_GAUGE.set(db.query(RiskEvent).count())
    JOBS_GAUGE.set(db.query(BackgroundJob).count())
    APPROVALS_PENDING_GAUGE.set(
        db.query(ApprovalRequest).filter(ApprovalRequest.status == "pending").count()
    )
    _set_grouped_gauge(db, PolicyDecision, POLICY_DECISIONS_GAUGE, ("action", "severity"))
    _set_grouped_gauge(db, PolicyPack, POLICY_PACKS_GAUGE, ("status",))
    _set_grouped_gauge(db, ScanRule, SCAN_RULES_GAUGE, ("status", "severity"))
    _set_grouped_gauge(db, McpServer, MCP_SERVERS_GAUGE, ("status",))
    _set_grouped_gauge(db, McpTool, MCP_TOOLS_GAUGE, ("status",))
    _set_grouped_gauge(db, BackgroundJob, JOBS_BY_STATUS_GAUGE, ("kind", "status"))
    _set_grouped_gauge(db, OutboxEvent, OUTBOX_BY_STATUS_GAUGE, ("status",))
    _set_grouped_gauge(db, ExecutionRequest, EXECUTIONS_BY_STATUS_GAUGE, ("status",))
    return PlainTextResponse(
        metrics_payload().decode("utf-8"), media_type="text/plain; version=0.0.4"
    )


def _set_grouped_gauge(db: Session, model, gauge, fields: tuple[str, ...]) -> None:
    columns = [getattr(model, field) for field in fields]
    rows = db.query(*columns, func.count()).group_by(*columns).all()
    gauge.clear()
    for row in rows:
        values = row[:-1]
        count = row[-1]
        gauge.labels(*[str(value or "unknown") for value in values]).set(count)


@v1_router.get("/system/status", response_model=SystemStatusOut)
def system_status(project_id: str = "default", db: Session = Depends(get_db)) -> SystemStatusOut:
    settings = get_settings()
    ensure_project(db, project_id)
    project = db.get(Project, project_id)
    try:
        db.execute(text("SELECT 1"))
        database = ComponentStatus(status="ok")
    except SQLAlchemyError:
        database = ComponentStatus(status="error", detail="Database unavailable")
    return SystemStatusOut(
        api=ComponentStatus(status="ok"),
        database=database,
        gateway=ComponentStatus(status="unknown", url="http://localhost:8001"),
        counts=SystemCounts(
            runs=db.query(Run).filter(Run.project_id == project_id).count(),
            risks=db.query(RiskEvent).filter(RiskEvent.project_id == project_id).count(),
            eval_suites=db.query(EvalSuite).filter(EvalSuite.project_id == project_id).count(),
            eval_runs=db.query(EvalRun).filter(EvalRun.project_id == project_id).count(),
            replays=db.query(ReplayRun).filter(ReplayRun.project_id == project_id).count(),
            mcp_servers=db.query(McpServer).filter(McpServer.project_id == project_id).count(),
            mcp_tools=db.query(McpTool).filter(McpTool.project_id == project_id).count(),
            pending_approvals=db.query(ApprovalRequest)
            .filter(ApprovalRequest.project_id == project_id, ApprovalRequest.status == "pending")
            .count(),
            policy_packs=db.query(PolicyPack).filter(PolicyPack.project_id == project_id).count(),
            scan_rules=db.query(ScanRule).filter(ScanRule.project_id == project_id).count(),
            active_suppressions=db.query(RunSuppression)
            .filter(RunSuppression.project_id == project_id, RunSuppression.status == "active")
            .count(),
        ),
        config=SystemConfig(
            project_id=project_id,
            store_raw_content=project.store_raw_content if project else settings.store_raw_content,
            policy_fail_mode=project.policy_fail_mode if project else settings.policy_fail_mode,
            retention_days=project.retention_days if project else settings.retention_days,
            status=project.status if project else "active",
        ),
    )
