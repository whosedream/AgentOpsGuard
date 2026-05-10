from fastapi import APIRouter, Depends, Response
from fastapi.responses import PlainTextResponse
from redis.exceptions import RedisError
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import ApprovalRequest, BackgroundJob, EvalRun, EvalSuite, McpServer, McpTool, PolicyDecision, PolicyPack, Project, ReplayRun, RiskEvent, Run, RunSuppression, ScanRule
from agentops_guard.backend.observability import request_metrics_lines
from agentops_guard.backend.schemas import ComponentStatus, SystemConfig, SystemCounts, SystemStatusOut
from agentops_guard.backend.services.jobs import redis_connection
from agentops_guard.backend.services.migrations import migration_status
from agentops_guard.backend.services.projects import ensure_project


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
    database = ComponentStatus(status="ok")
    redis = ComponentStatus(status="ok", url=get_settings().redis_url)
    status_code = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        status_code = "error"
        database = ComponentStatus(status="error", detail=str(exc))
    migration = migration_status(db) if database.status == "ok" else ComponentStatus(status="error", detail="database unavailable")
    if migration.status == "error":
        status_code = "error"
    try:
        redis_connection().ping()
    except RedisError as exc:
        status_code = "error"
        redis = ComponentStatus(status="error", detail=str(exc), url=get_settings().redis_url)
    if status_code != "ok":
        response.status_code = 503
    return {"status": ComponentStatus(status=status_code), "database": database, "redis": redis, "migration": migration}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)) -> PlainTextResponse:
    lines = [
        *request_metrics_lines(),
        "# HELP agentops_runs_total Total runs",
        "# TYPE agentops_runs_total gauge",
        f"agentops_runs_total {db.query(Run).count()}",
        "# HELP agentops_risks_total Total risk events",
        "# TYPE agentops_risks_total gauge",
        f"agentops_risks_total {db.query(RiskEvent).count()}",
        "# HELP agentops_jobs_total Total background jobs",
        "# TYPE agentops_jobs_total gauge",
        f"agentops_jobs_total {db.query(BackgroundJob).count()}",
        "# HELP agentops_policy_decisions_total Total policy decisions by action and severity",
        "# TYPE agentops_policy_decisions_total gauge",
        *grouped_metric_lines(db, PolicyDecision, "agentops_policy_decisions_total", ("action", "severity")),
        "# HELP agentops_approvals_pending Total pending approvals",
        "# TYPE agentops_approvals_pending gauge",
        f'agentops_approvals_pending {db.query(ApprovalRequest).filter(ApprovalRequest.status == "pending").count()}',
        "# HELP agentops_policy_packs_total Total policy packs by status",
        "# TYPE agentops_policy_packs_total gauge",
        *grouped_metric_lines(db, PolicyPack, "agentops_policy_packs_total", ("status",)),
        "# HELP agentops_scan_rules_total Total scan rules by status and severity",
        "# TYPE agentops_scan_rules_total gauge",
        *grouped_metric_lines(db, ScanRule, "agentops_scan_rules_total", ("status", "severity")),
        "# HELP agentops_mcp_servers_total Total MCP servers by status",
        "# TYPE agentops_mcp_servers_total gauge",
        *grouped_metric_lines(db, McpServer, "agentops_mcp_servers_total", ("status",)),
        "# HELP agentops_mcp_tools_total Total MCP tools by status",
        "# TYPE agentops_mcp_tools_total gauge",
        *grouped_metric_lines(db, McpTool, "agentops_mcp_tools_total", ("status",)),
        "# HELP agentops_jobs_by_status_total Total background jobs by kind and status",
        "# TYPE agentops_jobs_by_status_total gauge",
        *grouped_metric_lines(db, BackgroundJob, "agentops_jobs_by_status_total", ("kind", "status")),
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


def grouped_metric_lines(db: Session, model, metric_name: str, fields: tuple[str, ...]) -> list[str]:
    columns = [getattr(model, field) for field in fields]
    rows = db.query(*columns, func.count()).group_by(*columns).all()
    lines = []
    for row in rows:
        values = row[:-1]
        count = row[-1]
        labels = ",".join(f'{field}="{metric_label(value)}"' for field, value in zip(fields, values, strict=True))
        lines.append(f"{metric_name}{{{labels}}} {count}")
    return lines


def metric_label(value: object) -> str:
    return str(value or "unknown").replace("\\", "\\\\").replace('"', '\"')


@v1_router.get("/system/status", response_model=SystemStatusOut)
def system_status(project_id: str = "default", db: Session = Depends(get_db)) -> SystemStatusOut:
    settings = get_settings()
    ensure_project(db, project_id)
    project = db.get(Project, project_id)
    try:
        db.execute(text("SELECT 1"))
        database = ComponentStatus(status="ok")
    except Exception as exc:
        database = ComponentStatus(status="error", detail=str(exc))
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
            pending_approvals=db.query(ApprovalRequest).filter(ApprovalRequest.project_id == project_id, ApprovalRequest.status == "pending").count(),
            policy_packs=db.query(PolicyPack).filter(PolicyPack.project_id == project_id).count(),
            scan_rules=db.query(ScanRule).filter(ScanRule.project_id == project_id).count(),
            active_suppressions=db.query(RunSuppression).filter(RunSuppression.project_id == project_id, RunSuppression.status == "active").count(),
        ),
        config=SystemConfig(
            project_id=project_id,
            store_raw_content=project.store_raw_content if project else settings.store_raw_content,
            policy_fail_mode=project.policy_fail_mode if project else settings.policy_fail_mode,
            retention_days=project.retention_days if project else settings.retention_days,
            status=project.status if project else "active",
        ),
    )
