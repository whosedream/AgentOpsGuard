from pathlib import Path
from typing import Optional
import time

import boto3
import typer
import uvicorn
import yaml
from redis.exceptions import RedisError
from rich import print
from rq import Queue
from sqlalchemy.exc import DBAPIError, TimeoutError as DatabaseTimeoutError

from agentops_guard.backend.database import SessionLocal, init_db
from agentops_guard.backend.schemas import EvalRunCreate, EvalSuiteCreate
from agentops_guard.backend.services.eval import create_eval_suite, run_eval
from agentops_guard.backend.services.execution_requests import reconcile_execution_leases
from agentops_guard.backend.services.jobs import (
    dispatch_outbox_batch,
    reconcile_background_job_leases,
    redis_connection,
)
from agentops_guard.backend.telemetry import configure_telemetry
from agentops_guard.backend.worker import DatabaseSafeWorker

app = typer.Typer(help="AgentOps Guard developer CLI")


@app.command()
def api(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """Run the FastAPI backend."""
    uvicorn.run("agentops_guard.backend.main:app", host=host, port=port, reload=reload)


@app.command()
def gateway(
    config: Optional[Path] = None, host: str = "127.0.0.1", port: int = 8001, reload: bool = False
) -> None:
    """Run the MCP gateway."""
    from agentops_guard.gateway.app import load_gateway_config

    if config:
        init_db()
        db = SessionLocal()
        try:
            load_gateway_config(str(config), db)
        finally:
            db.close()
    uvicorn.run("agentops_guard.gateway.app:app", host=host, port=port, reload=reload)


@app.command("load-mcp-config")
def load_mcp_config(config: Path) -> None:
    """Load MCP gateway YAML into the registry."""
    from agentops_guard.gateway.app import load_gateway_config

    init_db()
    db = SessionLocal()
    try:
        load_gateway_config(str(config), db)
    finally:
        db.close()
    print(f"[green]Loaded MCP config:[/green] {config}")


@app.command("run-eval")
def run_eval_file(path: Path, project_id: str = "default") -> None:
    """Run an eval YAML/JSON file with built-in scanner and policy assertions."""
    init_db()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = data.get("cases", data if isinstance(data, list) else [])
    db = SessionLocal()
    try:
        suite = create_eval_suite(
            db,
            EvalSuiteCreate(project_id=project_id, name=data.get("name", path.stem), cases=cases),
        )
        result = run_eval(db, EvalRunCreate(project_id=project_id, suite_id=suite.id))
        db.commit()
    finally:
        db.close()
    print(
        {
            "id": result.id,
            "status": result.status,
            "passed": result.passed,
            "summary": result.summary,
        }
    )


@app.command("install-scanner-rule-pack")
def install_scanner_pack(path: Path, project_id: str = "default") -> None:
    """Idempotently install a reviewed, versioned scanner rule pack."""
    from agentops_guard.backend.services.scanner_rule_packs import install_scanner_rule_pack

    init_db()
    db = SessionLocal()
    try:
        result = install_scanner_rule_pack(db, project_id=project_id, path=path)
        db.commit()
    finally:
        db.close()
    print(result)


@app.command("worker")
def worker(queue: str = "default", burst: bool = False, with_scheduler: bool = False) -> None:
    """Run the Redis/RQ worker for AgentOps background jobs."""
    configure_telemetry("agentops-guard-worker")
    init_db()
    connection = redis_connection()
    try:
        connection.ping()
    except RedisError as exc:
        raise typer.Exit("Redis queue unavailable") from exc
    worker_instance = DatabaseSafeWorker([Queue(queue, connection=connection)], connection=connection)
    worker_instance.work(burst=burst, with_scheduler=with_scheduler)


@app.command("outbox-dispatcher")
def outbox_dispatcher(
    dispatcher_id: str = "dispatcher-1",
    once: bool = False,
    poll_seconds: float = 1.0,
) -> None:
    """Reliably deliver committed background jobs to Redis/RQ."""
    from agentops_guard.backend.database_resilience import database_unavailable
    from agentops_guard.backend.services.tool_invocations import reconcile_invocations
    from agentops_guard.backend.services.jobs import reconcile_missing_tool_deliveries

    init_db()
    delivery_cursor = None
    while True:
        db = SessionLocal()
        try:
            reconcile_execution_leases(db)
            reconcile_background_job_leases(db)
            reconcile_invocations(db)
            _, next_cursor = reconcile_missing_tool_deliveries(db, after_id=delivery_cursor)
            db.commit()
            delivery_cursor = next_cursor
            dispatch_outbox_batch(db, dispatcher_id=dispatcher_id)
        except (DBAPIError, DatabaseTimeoutError) as error:
            db.rollback()
            if once or not database_unavailable(error):
                raise
            # Retry delivery after failover, never the external action itself.
            print("Outbox database unavailable; committed tasks remain pending.")
        finally:
            db.close()
        if once:
            return
        time.sleep(poll_seconds)


@app.command("receipt-reconciler")
def receipt_reconciler(once: bool = False, poll_seconds: float = 10.0) -> None:
    """Query reviewed downstream receipts in a separate bounded worker; never replay tools."""
    from agentops_guard.backend.database_resilience import database_unavailable
    from agentops_guard.backend.services.tool_receipts import reconcile_batch

    if poll_seconds < 1:
        raise typer.BadParameter("poll-seconds must be at least 1")
    init_db()
    cursor = None
    while True:
        with SessionLocal() as db:
            try:
                counts, cursor = reconcile_batch(db, after_id=cursor)
                db.commit()
                if counts["queried"]:
                    print(counts)
            except (DBAPIError, DatabaseTimeoutError) as error:
                db.rollback()
                if once or not database_unavailable(error):
                    raise
                print("Receipt database unavailable; no external actions replayed.")
        if once:
            return
        time.sleep(poll_seconds)


@app.command("audit-anchor-exporter")
def audit_anchor_exporter(
    once: bool = False,
    poll_seconds: float = 300.0,
) -> None:
    """Copy verified public audit checkpoints to S3 Object Lock storage."""
    from agentops_guard.backend.config import get_settings
    from agentops_guard.backend.services.audit_anchors import (
        AuditAnchorUnavailable,
        InvalidAuditCheckpoint,
        S3ObjectLockSink,
        export_audit_checkpoints,
    )
    from agentops_guard.backend.services.audit_checkpoints import configured_audit_signer

    settings = get_settings()
    if settings.audit_anchor_backend != "s3_object_lock":
        raise typer.BadParameter("S3 Object Lock audit anchor export is disabled")
    assert settings.audit_anchor_s3_bucket is not None
    init_db()
    client = boto3.client(
        "s3",
        region_name=settings.audit_anchor_s3_region,
        endpoint_url=settings.audit_anchor_s3_endpoint_url,
    )
    sink = S3ObjectLockSink(
        client=client,
        bucket=settings.audit_anchor_s3_bucket,
        prefix=settings.audit_anchor_s3_prefix,
        retention_days=settings.audit_anchor_s3_retention_days,
        expected_bucket_owner=settings.audit_anchor_s3_expected_bucket_owner,
    )
    signer = configured_audit_signer()
    while True:
        db = SessionLocal()
        try:
            receipts = export_audit_checkpoints(db, sink=sink, signer=signer)
        except (AuditAnchorUnavailable, InvalidAuditCheckpoint) as exc:
            print({"status": "failed", "reason": "audit_anchor_verification_or_storage_failed"})
            raise typer.Exit(code=1) from exc
        finally:
            db.close()
        print({"status": "ok", "exported_or_verified": len(receipts)})
        if once:
            return
        time.sleep(poll_seconds)
