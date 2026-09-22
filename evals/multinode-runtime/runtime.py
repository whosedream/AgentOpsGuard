"""Controlled real-MCP upstream and test-only, transaction-bound scan receipts.

No customer tools or data. Seed output is consumed only by the trusted test
controller; it must never be streamed to a model or saved in reports.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import Counter
from contextvars import ContextVar
from contextlib import ExitStack, contextmanager
from functools import wraps
from pathlib import Path

from sqlalchemy import text, event as sqlalchemy_event
from sqlalchemy.exc import SQLAlchemyError

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.database_resilience import check_database_ready

request_context = ContextVar("eval_request_id", default=None)
stage_context = ContextVar("eval_stages", default=None)
RECEIPT_FIXTURE_PATH = Path("/app/receipt_mcp_server.py")
RECEIPT_FIXTURE_URL = "http://receipt-upstream:8092/mcp"


@contextmanager
def stage_measurement(stage):
    started, success = time.monotonic(), False
    try:
        yield
        success = True
    finally:
        stages = stage_context.get()
        if stages is not None:
            item = stages.setdefault(stage, {"ms": 0.0, "calls": 0, "errors": 0})
            item["ms"] += round((time.monotonic() - started) * 1000, 3)
            item["calls"] += 1
            item["errors"] += int(not success)


def measured(function, stage):
    @wraps(function)
    def wrapper(*args, **kwargs):
        with stage_measurement(stage):
            return function(*args, **kwargs)
    return wrapper


def database_error_event(context):
    code = getattr(context.original_exception, "sqlstate", None)
    # Never serialize the exception, SQL, parameters, or arbitrary server text.
    allowed = {"25006", "57P01", "57P02", "57P03", "53300", "57014", "55P03",
               "08000", "08001", "08003", "08004", "08006", "08007", "08P01"}
    event("database_error", request_context.get(),
          code=code if isinstance(code, str) and code in allowed else "unclassified",
          disconnect=bool(context.is_disconnect))
    # Observation only; SQLAlchemy must still propagate the original failure.


async def upstream_ready(_request):
    import anyio
    from fastapi import HTTPException
    from starlette.responses import Response

    try:
        # A listening TCP socket alone does not prove that this instance can
        # reach the current primary. Reuse the real application's bounded check.
        await anyio.to_thread.run_sync(check_database_ready, engine)
    except HTTPException as error:
        if error.status_code != 503:
            raise
        return Response(status_code=503)
    return Response(status_code=200)


def event(stage, request_id, **fields):
    if not isinstance(request_id, str) or not re.fullmatch(
        r"mn_[0-9a-f]{12}:\d+|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", request_id
    ):
        return
    print("EVAL_EVENT " + json.dumps({"stage": stage, "id": request_id,
        "instance": os.environ.get("HOSTNAME", "unknown"), "wall": time.time(),
        "monotonic": time.monotonic(), **fields}), flush=True)


def tables():
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE IF NOT EXISTS eval_database_probe (id integer PRIMARY KEY, value integer NOT NULL)"))
        connection.execute(text("INSERT INTO eval_database_probe VALUES (1,0) ON CONFLICT(id) DO NOTHING"))
        connection.execute(text("""CREATE TABLE IF NOT EXISTS eval_tool_receipts (
            request_id text PRIMARY KEY, phase text NOT NULL, kind text NOT NULL,
            executions integer NOT NULL DEFAULT 1)"""))
        connection.execute(text("""CREATE TABLE IF NOT EXISTS eval_scan_receipts (
            content_ref text PRIMARY KEY, phase text NOT NULL, status text NOT NULL,
            reason text, attempts integer NOT NULL, attempt_errors jsonb NOT NULL,
            request_id text,
            created_at timestamptz NOT NULL DEFAULT now())"""))


def database_probe(_data):
    """Role checks and confirmed COMMIT are distinct; only mutate the eval counter."""
    started = time.monotonic()
    result = {"role_writable": False, "commit_confirmed": False, "primary_address": None}
    try:
        with engine.begin() as connection:
            result["checkout_ms"] = round((time.monotonic() - started) * 1000, 3)
            connection.execute(text("SET LOCAL statement_timeout='500ms'"))
            connection.execute(text("SET LOCAL lock_timeout='250ms'"))
            role, address = connection.execute(text(
                "SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off', inet_server_addr()::text"
            )).one()
            result.update(role_writable=role, primary_address=address)
            from agentops_guard.backend.database_diagnostics import postgres_wait_snapshot
            result["diagnostics"] = postgres_wait_snapshot(connection)
            connection.execute(text("UPDATE eval_database_probe SET value=value+1 WHERE id=1"))
        result["commit_confirmed"] = True
    except SQLAlchemyError as error:
        code = getattr(getattr(error, "orig", None), "sqlstate", None)
        result["error"] = code if code in {"25006", "57014", "55P03", "57P01", "57P02", "57P03"} else "unavailable"
    result["total_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def admission_database_probe(_data):
    """Observe the independent admission DB, never infer it from business PG."""
    from agentops_guard.admission.store import AdmissionSettings, Store
    from agentops_guard.backend.database_diagnostics import postgres_wait_snapshot

    store = Store(AdmissionSettings())
    started = time.monotonic()
    result = {"database_target": "admission", "role_writable": False,
              "commit_confirmed": False, "primary_address": None}
    try:
        with store.sessions() as db:
            connection = db.connection()
            result["checkout_ms"] = round((time.monotonic() - started) * 1000, 3)
            db.execute(text("SET LOCAL statement_timeout='500ms'"))
            db.execute(text("SET LOCAL lock_timeout='250ms'"))
            role, address = db.execute(text(
                "SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off', inet_server_addr()::text"
            )).one()
            result.update(role_writable=role, primary_address=address)
            result["diagnostics"] = postgres_wait_snapshot(connection)
            changed = db.execute(text("UPDATE eval_database_probe SET value=value+1 WHERE id=1"))
            if changed.rowcount != 1:
                raise ValueError("Controlled admission probe counter is missing")
            # Uses the same WARNING-aware durability confirmation as deposits.
            store.confirm_commit(db, None)
            result["commit_confirmed"] = True
    except SQLAlchemyError as error:
        code = getattr(getattr(error, "orig", None), "sqlstate", None)
        result["error"] = code if code in {"25006", "57014", "55P03", "57P01", "57P02", "57P03"} else "unavailable"
    finally:
        store.dispose()
    result["total_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def upstream():
    from mcp.server import MCPServer

    corpus = json.load(open("/eval-data/payloads.json"))
    server = MCPServer("controlled-multinode-upstream")
    server.custom_route("/readyz", methods=["GET"])(upstream_ready)

    def receipt(request_id, kind):
        event("receipt_start", request_id)
        try:
            with engine.begin() as connection:
                connection.execute(text("""INSERT INTO eval_tool_receipts(request_id, phase, kind)
                    VALUES (:id, :phase, :kind) ON CONFLICT(request_id)
                    DO UPDATE SET executions=eval_tool_receipts.executions+1"""),
                    {"id": request_id, "phase": request_id.split(":")[0], "kind": kind})
                event("receipt_commit_start", request_id)
            event("receipt_committed", request_id)
        except SQLAlchemyError:
            event("receipt_database_error", request_id)
            raise  # Preserve failure; never replay the receipt or tool.

    @server.tool()
    def read_status(request_id: str, variant: str) -> str:
        receipt(request_id, "read")
        if variant == "attack":
            return corpus["attacks"][int(request_id.split(":")[1]) % len(corpus["attacks"])]
        if variant == "long":
            return "项目季度状态正常，测试记录均已归档。" * 400
        return "Service status is healthy."

    @server.tool()
    def write_file(request_id: str, path: str, content: str) -> str:
        receipt(request_id, "write")
        return "Controlled receipt only; no file was written."

    server.run(transport="streamable-http", host="0.0.0.0", port=8091,
               stateless_http=True, json_response=True)


def seed(data):
    from agentops_guard.backend.models import McpServer, McpTool, ToolExecutionPolicy
    from agentops_guard.backend.services.api_keys import create_api_key
    from agentops_guard.backend.services.projects import ensure_project
    from agentops_guard.backend.services.scanner_rule_packs import install_scanner_rule_pack
    from pathlib import Path

    phase = data["phase"]
    tables()
    with SessionLocal() as db:
        ensure_project(db, phase)
        install_scanner_rule_pack(db, project_id=phase,
            path=Path("/app/policies/scanner/agentdojo-important-instructions-v1.json"))
        server_id = phase + "_upstream"
        db.add(McpServer(id=server_id, project_id=phase, name="controlled upstream",
            transport="streamable_http", url="http://agentops-guard-gateway-proxy:8091/mcp", trust_level="internal",
            allowed_agents=[], status="active"))
        for name in ("read_status", "write_file"):
            properties = {"request_id": {"type": "string"}}
            if name == "read_status":
                properties["variant"] = {"type": "string"}
            else:
                properties.update(path={"type": "string"}, content={"type": "string"})
            db.add(McpTool(id=f"{server_id}:{name}", project_id=phase, server_id=server_id,
                name=name, description=name.replace("_", " "), status="active",
                input_schema={"type": "object", "properties": properties,
                              "required": list(properties)},
                annotations={"readOnlyHint": name == "read_status"}))
        if data.get("queue_policy"):
            from agentops_guard.backend.services.tool_invocations import current_revision
            import hashlib
            # SessionLocal disables autoflush; revision lookup must see the
            # newly registered test server/tools in this same transaction.
            db.flush()
            for name in ("read_status", "write_file"):
                tool_id = f"{server_id}:{name}"
                revision = current_revision(db, phase, tool_id)
                # This controller reviews ONLY the two fixed test tools defined
                # above. Never infer capability from a server's annotations.
                db.add(ToolExecutionPolicy(tool_id=tool_id, project_id=phase,
                    revision_digest=revision.content_digest, queue_enabled=True,
                    retry_mode="never", updated_by="controlled-eval-admin",
                    evidence_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
        key, token = create_api_key(db, phase, "multinode-load", ["mcp:read", "mcp:invoke"],
                                  agent_id="controlled-load")
        key_id = key.id
        db.commit()
    return {"token": token, "server_id": server_id, "key_id": key_id}


def register_receipt_fixture(db, phase, *, result_recovery=False, read_status=False):
    """Review only the frozen synthetic fixture, never self-reported tool hints."""
    import hashlib
    from agentops_guard.backend.models import McpServer, McpTool, ToolExecutionPolicy
    from agentops_guard.backend.services.projects import ensure_project
    from agentops_guard.backend.services.tool_invocations import current_revision
    from agentops_guard.backend.services.tool_receipts import ReceiptContract, validate_contract

    if read_status and not result_recovery:
        raise ValueError("Controlled status reads require a result recovery contract")
    suffix = "_v2" if result_recovery else ""
    action, lookup_name = "echo" + suffix, "lookup_receipt" + suffix
    if read_status:
        action = "read_status_v2"
    server_id = phase + "_receipts"
    ensure_project(db, phase)
    db.add(McpServer(id=server_id, project_id=phase, name="controlled independent receipt fixture",
        transport="streamable_http", url=RECEIPT_FIXTURE_URL,
        trust_level="internal", allowed_agents=[], status="active"))
    properties = {"operation_id": {"type": "string"}, "crash_after_commit": {"type": "boolean"}}
    if read_status:
        properties.update(request_id={"type": "string"}, variant={"type": "string"})
        required = ["request_id", "variant"]
    else:
        properties["text"] = {"type": "string"}
        required = ["text"]
    descriptors = [(action, properties, required),
        (lookup_name, {"operation_id": {"type": "string"}}, ["operation_id"])]
    if suffix:
        descriptors.append(("lookup_result_v2", {"operation_id": {"type": "string"}}, ["operation_id"]))
    for name, properties, required in descriptors:
        db.add(McpTool(id=f"{server_id}:{name}", project_id=phase, server_id=server_id,
            name=name, description="Controlled receipt test", status="active", annotations={},
            input_schema={"type": "object", "properties": properties, "required": required}))
    db.flush()
    revision = current_revision(db, phase, server_id + ":" + action)
    lookup = current_revision(db, phase, server_id + ":" + lookup_name)
    result_fields = {}
    if suffix:
        result_fields = {"protocol": "agentops-receipt-v2", "result_tool_id": server_id + ":lookup_result_v2",
            "result_revision_digest": current_revision(db, phase, server_id + ":lookup_result_v2").content_digest}
        if read_status:
            result_fields["max_result_bytes"] = 65_536  # Original long Chinese output exceeds the pilot's 16 KiB.
    contract = ReceiptContract(**result_fields, key_argument="operation_id", lookup_tool_id=server_id + ":" + lookup_name,
        lookup_revision_digest=lookup.content_digest, retention_seconds=3600)
    validate_contract(db, phase, server_id + ":" + action, contract)
    db.add(ToolExecutionPolicy(tool_id=server_id + ":" + action, project_id=phase,
        revision_digest=revision.content_digest, queue_enabled=True, retry_mode="never",
        updated_by="controlled-eval-admin", receipt_contract=contract.model_dump(),
        evidence_sha256=hashlib.sha256(RECEIPT_FIXTURE_PATH.read_bytes()).hexdigest()))
    return server_id, action


def seed_receipts(data):
    from agentops_guard.backend.services.api_keys import create_api_key

    phase = data["phase"]
    with SessionLocal() as db:
        server_id, _ = register_receipt_fixture(db, phase, result_recovery=bool(data.get("result_recovery")))
        _, token = create_api_key(db, phase, "receipt-validation", ["mcp:read", "mcp:invoke"],
                                 agent_id="controlled-load")
        db.commit()
    return {"token": token, "server_id": server_id}


def seed_admission(data):
    from agentops_guard.admission.importer import provision
    from agentops_guard.admission.store import AdmissionSettings, Store

    seeded = seed({**data, "queue_policy": True})
    store = Store(AdmissionSettings())
    try:
        # Synthetic diagnostics only; create before load, not during a fault.
        with store.engine.begin() as connection:
            connection.execute(text("CREATE TABLE IF NOT EXISTS eval_database_probe (id integer PRIMARY KEY, value integer NOT NULL)"))
            connection.execute(text("INSERT INTO eval_database_probe VALUES (1,0) ON CONFLICT(id) DO NOTHING"))
        with SessionLocal() as db:
            read_server, read_tool = seeded["server_id"], "read_status"
            if data.get("result_recovery"):
                read_server, read_tool = register_receipt_fixture(db, data["phase"], result_recovery=True, read_status=True)
                db.flush()
            grant, token = provision(store, db, key_id=seeded["key_id"],
                tool_ids=[read_server + ":" + read_tool, seeded["server_id"] + ":write_file"])
        return {**seeded, "admission_token": token, "grant_id": grant,
                "read_server_id": read_server, "read_tool": read_tool,
                "read_argument_mode": "request_variant", "result_recovery": bool(data.get("result_recovery"))}
    finally:
        store.engine.dispose()


def receipt_binding(data):
    from agentops_guard.backend.models import ToolInvocation

    with SessionLocal() as db:
        row = db.query(ToolInvocation).filter_by(project_id=data["phase"], request_id=data["request_id"]).one()
        return {"operation_id": row.receipt_binding["operation_id"]}


def receipt_measurement(function):
    @wraps(function)
    def measured_receipt(db, row):
        # Recovery has no original payload after dispatch. The durable UUID is
        # sufficient: the controller already maps it to the phase:index ID.
        token = request_context.set(row.request_id)
        try:
            return function(db, row)
        finally:
            request_context.reset(token)
    return measured_receipt


def stats(data):
    from agentops_guard.backend.models import PolicyDecision, RiskEvent, ToolInvocation, BackgroundJob, OutboxEvent
    from agentops_guard.backend.services.tool_invocations import public_status
    from agentops_guard.backend.services.audit import verify_audit_chain

    phase = data["phase"]
    with SessionLocal() as db:
        receipts = db.execute(text("SELECT request_id,kind,executions FROM eval_tool_receipts WHERE phase=:phase"),
                              {"phase": phase}).all()
        scans = db.execute(text("SELECT status,reason,count(*) FROM eval_scan_receipts WHERE phase=:phase GROUP BY status,reason"),
                           {"phase": phase}).all()
        scoring_attempts = db.execute(text("SELECT attempts,attempt_errors FROM eval_scan_receipts WHERE phase=:phase"),
                           {"phase": phase}).all()
        scoring_requests = db.execute(text(
            "SELECT request_id,content_ref,status,reason FROM eval_scan_receipts WHERE phase=:phase"),
            {"phase": phase}).all()
        decisions = {row[0] for row in db.query(PolicyDecision.id).filter_by(project_id=phase)}
        errors = db.query(RiskEvent).filter_by(project_id=phase, risk_type="semantic_scanner_error").count()
        audit = verify_audit_chain(db, phase)
        invocation_rows = [{"requestId": row.request_id, "state": public_status(row)["state"],
            "attempts": row.attempts, "updated_at": row.updated_at.isoformat(),
            "receipt_bound": bool(row.receipt_binding), "result_stored": bool(row.encrypted_result),
            "result_recovered": (row.summary or {}).get("code") == "downstream_result_recovered",
            "result_scanned": (row.summary or {}).get("resultScanned") is True}
            for row in db.query(ToolInvocation).filter_by(project_id=phase)]
        jobs = dict(Counter(row[0] for row in db.query(BackgroundJob.status).filter_by(project_id=phase)))
        outbox = dict(Counter(row[0] for row in db.query(OutboxEvent.status).filter_by(project_id=phase)))
    reads = {row.request_id for row in receipts if row.kind == "read"}
    acknowledged = set(data["acknowledged_reads"])
    confirmed = set(data.get("explicit_response_confirmations", []))
    reasons = Counter({reason or status: count for status, reason, count in scans})
    return {"upstream_reads": len(reads), "duplicate_executions": sum(row.executions-1 for row in receipts),
        "unauthorized_writes": sum(row.executions for row in receipts if row.kind == "write"),
        "acknowledged_missing_receipts": len(acknowledged-reads),
        "executed_without_acknowledgement": len(reads-acknowledged),
        "executed_with_failure_confirmation": len((reads-acknowledged) & confirmed),
        "executed_without_any_confirmation": len(reads-acknowledged-confirmed),
        "unacknowledged_read_ids": sorted(reads-acknowledged),
        "missing_persisted_decisions": len(set(data["decision_ids"])-decisions),
        "completed_scans": sum(count for status, _, count in scans if status == "ok"),
        "scan_attempts": sum(count for _, _, count in scans),
        "scoring_http_attempts": sum(row.attempts for row in scoring_attempts),
        "scoring_attempt_errors": dict(Counter(reason for row in scoring_attempts for reason in row.attempt_errors)),
        "scan_error_reasons": {key: value for key, value in reasons.items() if key != "ok"},
        "semantic_error_events": errors, "audit_valid": audit.valid,
        "scoring_requests": [{"request_id": row.request_id, "content_ref": row.content_ref,
            "status": row.status, "reason": row.reason} for row in scoring_requests],
        "invocations": invocation_rows, "job_status_counts": jobs, "outbox_status_counts": outbox,
        "audit_entries": audit.checked_entries}


def configure_gateway_observers():
    from agentops_guard.backend.services import scanner
    from agentops_guard.backend.services.semantic_scanner import SEMANTIC_SOURCES

    actual_scan = scanner.scan_content

    def record_scan(request, db=None):
        result = actual_scan(request, db)
        if db is not None and request.source in SEMANTIC_SOURCES:
            assessment = result.semantic_assessment
            db.execute(text("""INSERT INTO eval_scan_receipts(content_ref,phase,status,reason,attempts,attempt_errors,request_id)
                VALUES (:ref,:phase,:status,:reason,:attempts,CAST(:errors AS jsonb),:request)"""),
                {"ref": result.sanitized_content_ref, "phase": request.project_id,
                 "status": assessment.status if assessment else "not_scored",
                 "reason": assessment.error_reason if assessment else "disabled",
                 "attempts": assessment.attempts if assessment else 0,
                 "errors": json.dumps(assessment.attempt_errors if assessment else []),
                 "request": request_context.get()})
            event("scoring_finished", request_context.get(),
                  status=assessment.status if assessment else "not_scored",
                  attempts=assessment.attempts if assessment else 0,
                  errors=assessment.attempt_errors if assessment else [])
        return result

    # Test instrumentation only: it calls the unmodified real scanner, and its
    # receipt commits in the same transaction as the gateway decision.
    scanner.scan_content = record_scan
    from agentops_guard.gateway import app as gateway_module
    from agentops_guard.backend.services import tool_invocations, tool_receipts
    from agentops_guard.backend import auth
    from sqlalchemy.orm import Session

    # Measurement only: no retry, changed timeout, arguments or swallowed error.
    engine.connect = measured(engine.connect, "database_checkout")
    auth.authenticate_bearer_token = measured(auth.authenticate_bearer_token, "authentication")
    Session.commit = measured(Session.commit, "database_commit")
    gateway_module.evaluate_policy = measured(gateway_module.evaluate_policy, "policy")
    gateway_module.scan_content = measured(gateway_module.scan_content, "scan")
    tool_invocations.InvocationAttempt.dispatch = measured(
        tool_invocations.InvocationAttempt.dispatch, "dispatch_commit")
    tool_invocations.register = measured(tool_invocations.register, "admission")
    tool_invocations._finish = measured(tool_invocations._finish, "finish_commit")
    tool_invocations.queued_identity = measured(tool_invocations.queued_identity, "execution_authority")
    original_slot = gateway_module.server_call_slot

    @contextmanager
    def capacity_slot(*args, **kwargs):
        with ExitStack() as stack:
            with stage_measurement("capacity_wait"):
                value = stack.enter_context(original_slot(*args, **kwargs))
            yield value

    gateway_module.server_call_slot = capacity_slot
    actual_perform = gateway_module._perform_tools_call

    def record_perform(payload, *args, **kwargs):
        # Worker runs lack HTTP middleware. Keep their measurements isolated.
        if stage_context.get() is not None:
            if request_context.get() is None:
                request_context.set(payload.get("arguments", {}).get("request_id"))
            return actual_perform(payload, *args, **kwargs)
        request_token = request_context.set(payload.get("arguments", {}).get("request_id"))
        stage_token = stage_context.set({})
        try:
            return actual_perform(payload, *args, **kwargs)
        finally:
            event("gateway_stages", request_context.get(), measurements=stage_context.get())
            stage_context.reset(stage_token)
            request_context.reset(request_token)

    gateway_module._perform_tools_call = record_perform
    actual_queued = tool_invocations.execute_queued

    @wraps(actual_queued)
    def record_queued(*args, **kwargs):
        request_token = request_context.set(None)
        stage_token = stage_context.set({})
        try:
            return actual_queued(*args, **kwargs)
        finally:
            event("gateway_stages", request_context.get(), measurements=stage_context.get())
            stage_context.reset(stage_token)
            request_context.reset(request_token)

    tool_invocations.execute_queued = record_queued
    tool_receipts.reconcile_receipt = receipt_measurement(tool_receipts.reconcile_receipt)

    actual_call = gateway_module._call_upstream_tool

    def record_call(server, name, arguments):
        request_id = arguments.get("request_id") or request_context.get()
        event("gateway_dispatch", request_id)
        with stage_measurement("upstream"):
            result = actual_call(server, name, arguments)
        code = (result.get("upstreamError") or {}).get("code") if isinstance(result, dict) else None
        event("gateway_tool_return", request_id,
              error=bool(isinstance(result, dict) and result.get("isError")),
              code=code if code in {"timeout", "http_error", "invalid_result"} else None)
        return result

    gateway_module._call_upstream_tool = record_call
    sqlalchemy_event.listen(engine, "handle_error", database_error_event)
    return gateway_module


def gateway():
    import anyio
    import uvicorn
    gateway_module = configure_gateway_observers()

    @gateway_module.app.middleware("http")
    async def instance_header(request, call_next):
        token = request_context.set(request.headers.get("X-Eval-Request"))
        stage_token = stage_context.set({})
        arrived = time.monotonic()
        pool = anyio.to_thread.current_default_thread_limiter()
        pool_state = pool.statistics()
        event("gateway_ingress", request_context.get(),
              borrowed_threads=pool_state.borrowed_tokens, waiting_threads=pool_state.tasks_waiting,
              total_threads=pool_state.total_tokens)
        try:
            response = await call_next(request)
            response.headers["X-Eval-Instance"] = os.environ.get("HOSTNAME", "unknown")
            return response
        finally:
            pool_state = pool.statistics()
            event("gateway_response", request_context.get(), elapsed_ms=(time.monotonic()-arrived)*1000,
                  borrowed_threads=pool_state.borrowed_tokens, waiting_threads=pool_state.tasks_waiting,
                  total_threads=pool_state.total_tokens)
            event("gateway_stages", request_context.get(), measurements=stage_context.get())
            stage_context.reset(stage_token)
            request_context.reset(token)

    uvicorn.run(gateway_module.app, host="0.0.0.0", port=8001, access_log=False)


def worker():
    configure_gateway_observers()
    from agentops_guard.cli import worker as run_worker
    run_worker(queue="default", with_scheduler=True)


def receipt_worker():
    configure_gateway_observers()
    from agentops_guard.cli import receipt_reconciler
    receipt_reconciler(poll_seconds=1)


if __name__ == "__main__":
    role = sys.argv[1]
    if role == "upstream":
        upstream()
    elif role == "gateway":
        gateway()
    elif role == "worker":
        worker()
    elif role == "receipt_worker":
        receipt_worker()
    elif role in {"seed", "stats", "database_probe", "admission_database_probe", "seed_receipts", "receipt_binding", "seed_admission"}:
        function = {"seed": seed, "stats": stats, "database_probe": database_probe,
                    "admission_database_probe": admission_database_probe,
                    "seed_receipts": seed_receipts, "receipt_binding": receipt_binding,
                    "seed_admission": seed_admission}[role]
        print(json.dumps(function(json.load(sys.stdin))), flush=True)
    else:
        raise ValueError("unknown controlled runtime role")
