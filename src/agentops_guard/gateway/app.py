from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import asyncio
from functools import partial
import json
from typing import Any

import anyio
import httpx
from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for
import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mcp.shared.uri_template import InvalidUriTemplate, UriTemplate
from sqlalchemy.orm import Session
from opentelemetry import trace

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import engine, get_db, init_db
from agentops_guard.backend.database_resilience import check_database_ready, database_http_boundary
from agentops_guard.backend.models import (
    ApprovalRequest,
    ContentObject,
    McpServer,
    McpTool,
    McpToolRevision,
    RiskEvent,
    Run,
)
from agentops_guard.backend.schemas import (
    PolicyContext,
    PolicyDecisionOut,
    ScanRequest,
    ScanResponse,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import (
    detect_secret_labels,
    redact_structured_value,
)
from agentops_guard.backend.services.content_provenance import (
    build_content_provenance,
    strip_untrusted_agentops_metadata,
)
from agentops_guard.backend.services.policy import (
    INTENT_MANIFEST_KEY,
    assess_tool_action_alignment,
    build_policy_snapshot,
    evaluate_builtin_policy,
    evaluate_policy,
    persist_policy_decision,
)
from agentops_guard.backend.services.opa import OpaUnavailable, check_opa_health
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.execution_requests import (
    ExecutionClaimConflict,
    create_execution_request,
    mark_execution_result,
    match_and_claim_execution,
    release_execution_claim,
)
from agentops_guard.backend.services.mcp_tool_revisions import record_tool_revision
from agentops_guard.backend.services.scanner import (
    EXTERNAL_CONTENT_QUARANTINE_LABELS,
    scan_content,
    should_quarantine_external_content,
)
from agentops_guard.backend.security.middleware import AuthContextLifecycleMiddleware
from agentops_guard.backend.services.semantic_scanner import (
    SemanticScannerUnavailable,
    semantic_scanner_ready,
)
from agentops_guard.backend.telemetry import TelemetryMiddleware, configure_telemetry
from agentops_guard.gateway.auth import (
    GatewayIdentity,
    require_gateway_invoke,
    require_gateway_read,
)
from agentops_guard.gateway.concurrency import (
    GatewayCapacityExceeded,
    GatewayCapacityUnavailable,
    server_call_slot,
)
from agentops_guard.gateway.protocol import create_standard_mcp_gateway
from agentops_guard.gateway.transports import LegacyHttpTransport, StreamableHttpTransport
from agentops_guard.gateway.transports.errors import UpstreamTransportError
from agentops_guard.gateway.transports.stdio import (
    close_stdio_managers,
    get_stdio_manager,
    safe_stdio_error_code,
)

router = APIRouter(prefix="/mcp")
_MAX_RESOURCE_TEMPLATE_LENGTH = 4_096
_MAX_RESOURCE_TEMPLATE_VARIABLES = 32
_MAX_RESOURCE_URI_LENGTH = 65_536
_MAX_STDIO_LIST_PAGES = 1_000
_MAX_COMPLETION_ARGUMENTS = 32
_MAX_COMPLETION_NAME_LENGTH = 128
_MAX_COMPLETION_VALUE_LENGTH = 512
_MAX_COMPLETION_VALUES = 100


@router.get("/tools/list")
def tools_list(
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    project_id = identity.project_id
    tools: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        if not _server_allows_identity(server, identity):
            continue
        upstream_tools = _load_tools_from_server(server)
        for raw_tool in upstream_tools:
            tool = strip_untrusted_agentops_metadata(raw_tool)
            if not isinstance(tool, dict):
                continue
            description = tool.get("description") or ""
            input_schema = tool.get("inputSchema", {})
            annotations = tool.get("annotations", {})
            scanned_text = json.dumps(tool, ensure_ascii=False, sort_keys=True)
            scan = scan_content(
                ScanRequest(
                    project_id=project_id,
                    content=scanned_text,
                    source="mcp_tool_description",
                ),
                db,
            )
            status = "quarantined" if should_quarantine_external_content(scan) else "active"
            quarantined = status == "quarantined"
            visible_description = "" if quarantined else description
            visible_input_schema = {} if quarantined else input_schema
            visible_annotations = {} if quarantined else annotations
            tool_id = f"{server.id}:{tool.get('name')}"
            existing = db.get(McpTool, tool_id)
            if existing:
                tool_row = existing
            else:
                tool_row = McpTool(
                    id=tool_id,
                    project_id=project_id,
                    server_id=server.id,
                    name=tool.get("name", "unknown"),
                )
                db.add(tool_row)
            tool_row.description = visible_description
            tool_row.input_schema = visible_input_schema
            tool_row.annotations = visible_annotations
            tool_row.risk_score = scan.risk_score
            tool_row.risk_labels = scan.risk_labels
            tool_row.status = status
            db.flush()
            revision = record_tool_revision(db, server, tool_row, source=tool)
            if not quarantined:
                tools.append(
                    {
                        **tool,
                        "description": visible_description,
                        "inputSchema": visible_input_schema,
                        "annotations": visible_annotations,
                        "serverId": server.id,
                        "riskScore": scan.risk_score,
                        "riskLabels": scan.risk_labels,
                        "status": status,
                        "revisionId": revision.id,
                        "provenance": _content_provenance(
                            db=db,
                            project_id=project_id,
                            source="mcp_tool_description",
                            origin_parts=(server.id, str(tool.get("name") or "")),
                            scan=scan,
                        ),
                    }
                )
    db.commit()
    return {"tools": tools}


@router.post("/tools/call")
def tools_call(
    payload: dict[str, Any],
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from agentops_guard.backend.services.tool_invocations import execute, public_status, register

    row, created = register(db, payload, identity, queued=False)
    if not created:
        return {"isError": True, "content": [{"type": "text", "text": "invocation_already_recorded"}],
                "invocation": public_status(row)}
    return execute(db, row, payload, identity, _perform_tools_call)


@router.post("/invocations", status_code=202)
def enqueue_tool_invocation(
    payload: dict[str, Any],
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from agentops_guard.backend.services.tool_invocations import public_status, register

    if not payload.get("requestId"):
        raise HTTPException(400, "Queued requests require a client-generated requestId UUID")
    row, _created = register(db, payload, identity, queued=True)
    return public_status(row)


@router.get("/invocations/{request_id}")
def get_tool_invocation(
    request_id: str,
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from agentops_guard.backend.services.tool_invocations import lookup, public_status

    return public_status(lookup(db, identity, request_id))


@router.post("/invocations/{request_id}/resume", status_code=202)
def resume_tool_invocation(
    request_id: str,
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from agentops_guard.backend.services.tool_invocations import lookup, resume

    return resume(db, lookup(db, identity, request_id))


@router.get("/invocations/{request_id}/result")
def get_invocation_result(
    request_id: str,
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from agentops_guard.backend.services.tool_invocations import lookup
    from agentops_guard.backend.services.tool_receipts import get_recovered_result

    return get_recovered_result(db, lookup(db, identity, request_id))


@router.post("/invocations/{request_id}/reconcile")
def reconcile_tool_invocation(
    request_id: str,
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from agentops_guard.backend.services.tool_invocations import lookup
    from agentops_guard.backend.services.tool_receipts import reconcile_receipt

    return reconcile_receipt(db, lookup(db, identity, request_id))


def _perform_tools_call(
    payload: dict[str, Any],
    identity: GatewayIdentity = Depends(require_gateway_invoke),
    db: Session = Depends(get_db),
    *,
    invocation_attempt=None,
) -> dict[str, Any]:
    project_id = identity.project_id
    tool_name = payload.get("name")
    server_id = payload.get("serverId")
    arguments = payload.get("arguments", {})
    run_id = payload.get("runId")
    idempotency_key = payload.get("idempotencyKey")
    claimed_agent_id = payload.get("agentId")
    if (
        not isinstance(tool_name, str)
        or not tool_name
        or not isinstance(server_id, str)
        or not server_id
    ):
        raise HTTPException(400, "name and serverId are required")
    if not isinstance(arguments, dict):
        raise HTTPException(400, "arguments must be an object")
    if run_id is not None and not isinstance(run_id, str):
        raise HTTPException(400, "runId must be a string")
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 128
    ):
        raise HTTPException(400, "idempotencyKey must be a non-empty string up to 128 characters")
    if claimed_agent_id is not None:
        if not isinstance(claimed_agent_id, str) or not claimed_agent_id:
            raise HTTPException(400, "agentId must be a non-empty string")
        if identity.agent_id != claimed_agent_id:
            raise HTTPException(403, "Agent identity does not match authenticated credential")
    server = (
        db.query(McpServer)
        .filter(
            McpServer.id == server_id,
            McpServer.project_id == project_id,
            McpServer.status == "active",
        )
        .one_or_none()
    )
    if not server:
        raise HTTPException(404, "MCP server not found")
    tool = (
        db.query(McpTool)
        .filter(
            McpTool.id == f"{server_id}:{tool_name}",
            McpTool.project_id == project_id,
        )
        .one_or_none()
    )
    if tool is None or tool.status != "active":
        raise HTTPException(404, "MCP tool not found")
    current_revision = (
        db.get(McpToolRevision, tool.current_revision_id)
        if tool.current_revision_id is not None
        else None
    )
    if tool.current_revision_id is not None and current_revision is None:
        raise HTTPException(409, "MCP tool revision is unavailable")
    revision = record_tool_revision(
        db,
        server,
        tool,
        source=current_revision.descriptor if current_revision is not None else None,
        source_digest=current_revision.source_digest if current_revision is not None else None,
    )
    intent_manifest = None
    run = None
    if run_id is not None:
        run = db.query(Run).filter(Run.id == run_id, Run.project_id == project_id).one_or_none()
        if run is None or (run.agent_id and run.agent_id != identity.agent_id):
            raise HTTPException(404, "Run not found")
        if run.status == "awaiting_approval":
            pending_approval = (
                db.query(ApprovalRequest)
                .filter(
                    ApprovalRequest.project_id == project_id,
                    ApprovalRequest.run_id == run_id,
                    ApprovalRequest.status == "pending",
                )
                .order_by(ApprovalRequest.created_at.desc())
                .first()
            )
            return _error_response(
                "run_awaiting_approval",
                approval_request_id=(pending_approval.id if pending_approval else None),
                execution_request_id=(
                    pending_approval.execution_request_id if pending_approval else None
                ),
            )
        if run.status != "running":
            raise HTTPException(409, "Run is not active")
        intent_manifest = (run.metadata_json or {}).get(INTENT_MANIFEST_KEY)
    tool_annotations = tool.annotations if tool and isinstance(tool.annotations, dict) else {}
    action_alignment = assess_tool_action_alignment(
        tool_name,
        arguments,
        tool_annotations,
        intent_manifest,
        server.trust_level,
    )
    untrusted_content_risk = False
    if run_id is not None and action_alignment["required"]:
        untrusted_content_risk = (
            db.query(RiskEvent.id)
            .filter(
                RiskEvent.project_id == project_id,
                RiskEvent.run_id == run_id,
                RiskEvent.risk_type.in_(
                    {
                        "semantic_prompt_injection",
                        "semantic_prompt_injection_shadow",
                    }
                ),
            )
            .first()
            is not None
        )
    argument_scan = scan_content(
        ScanRequest(
            project_id=project_id,
            run_id=run_id,
            content=json.dumps(arguments, ensure_ascii=False, sort_keys=True),
            source="mcp_tool_arguments",
        ),
        db,
    )
    context = PolicyContext(
        project_id=project_id,
        run_id=run_id,
        actor=identity.policy_actor,
        tool={
            "name": tool_name,
            "server_id": server_id,
            "status": tool.status if tool else "active",
            "allowed_agents": server.allowed_agents or [],
            "server_trust_level": server.trust_level,
            "annotations": tool_annotations,
            "args": arguments,
        },
        risk_score=argument_scan.risk_score,
        risk_labels=argument_scan.risk_labels,
        data={
            "labels": argument_scan.risk_labels,
            "content_source": "mcp_tool_arguments",
            "trust": "agent_generated",
            "action_alignment": action_alignment,
            "untrusted_content_risk": untrusted_content_risk,
        },
        metadata={
            "content_source": "mcp_tool_arguments",
            "trust": "agent_generated",
            "original_intent_source": "run.input_ref" if run_id else None,
            "tool_revision_id": revision.id,
            "tool_revision_digest": revision.content_digest,
        },
    )
    audit_context = context.model_copy(
        update={
            "tool": {
                **context.tool,
                "args": {"sanitized_content_ref": argument_scan.sanitized_content_ref},
            }
        }
    )
    evaluated = evaluate_policy(context, db)
    evaluated = evaluated.model_copy(
        update={
            "context": {
                **evaluated.context,
                "tool": audit_context.tool,
            }
        }
    )
    execution_request = None
    settings = get_settings()
    policy_snapshot = build_policy_snapshot(db, evaluated, audit_context)
    if evaluated.action == "require_approval":
        execution_match = match_and_claim_execution(
            db,
            project_id=project_id,
            run_id=run_id,
            subject=identity.policy_actor,
            server_id=server_id,
            tool_name=tool_name,
            tool_revision_id=revision.id,
            tool_revision_digest=revision.content_digest,
            arguments=arguments,
            policy_snapshot=policy_snapshot,
            claimant=identity.actor_id,
            idempotency_key=idempotency_key,
            lease_seconds=max(settings.gateway_call_timeout_seconds + 10.0, 60.0),
        )
        execution_request = execution_match.request
        if execution_match.kind == "waiting":
            assert execution_request is not None
            db.commit()
            return _error_response(
                evaluated.reason_code,
                policy_decision=evaluated.model_dump(),
                risk=argument_scan.model_dump(),
                approval_request_id=execution_request.approval_id,
                execution_request_id=execution_request.id,
            )
        if execution_match.kind in {"stale", "terminal"}:
            assert execution_request is not None
            db.commit()
            return _error_response(
                f"execution_request_{execution_request.status}",
                policy_decision=evaluated.model_dump(),
                risk=argument_scan.model_dump(),
                approval_request_id=execution_request.approval_id,
                execution_request_id=execution_request.id,
            )
        if execution_match.kind == "claimed":
            assert execution_request is not None
            evaluated = PolicyDecisionOut(
                action="allow",
                reason_code="approved_execution_request",
                severity=evaluated.severity,
                matched_policy="human_approval",
                context={
                    **evaluated.context,
                    "approval_request_id": execution_request.approval_id,
                    "execution_request_id": execution_request.id,
                },
            )
    decision = persist_policy_decision(db, evaluated, audit_context)
    approval_request_id = None
    if decision.action == "require_approval":
        approval = (
            db.query(ApprovalRequest).filter(ApprovalRequest.decision_id == decision.id).one()
        )
        approval_request_id = approval.id
        execution_request = create_execution_request(
            db,
            approval=approval,
            decision_id=decision.id or "",
            project_id=project_id,
            run_id=run_id,
            subject=identity.policy_actor,
            server_id=server_id,
            tool_name=tool_name,
            tool_revision_id=revision.id,
            tool_revision_digest=revision.content_digest,
            arguments=arguments,
            intent_ref=run.input_ref if run is not None else None,
            policy_snapshot=policy_snapshot,
            risk_score=argument_scan.risk_score,
            risk_labels=argument_scan.risk_labels,
            idempotency_key=idempotency_key,
        )
    if decision.action != "allow":
        db.commit()
        return _error_response(
            decision.reason_code,
            policy_decision=decision.model_dump(),
            risk=argument_scan.model_dump(),
            approval_request_id=approval_request_id,
            execution_request_id=execution_request.id if execution_request else None,
        )
    db.commit()
    try:
        with server_call_slot(
            server.id,
            limit=settings.gateway_max_concurrency_per_server,
            wait_seconds=settings.gateway_capacity_wait_seconds,
            backend=settings.gateway_concurrency_backend,
            redis_url=settings.redis_url,
            lease_seconds=max(
                settings.gateway_concurrency_lease_seconds,
                settings.gateway_call_timeout_seconds + 10.0,
            ),
        ):
            with trace.get_tracer("agentops_guard.gateway").start_as_current_span(
                "mcp.tool.call",
                attributes={
                    "mcp.transport": server.transport,
                    "mcp.runtime_provider": server.runtime_provider,
                },
            ) as upstream_span:
                if invocation_attempt is not None:
                    invocation_attempt.dispatch(db, revision.content_digest)
                result = strip_untrusted_agentops_metadata(
                    _call_upstream_tool(server, tool_name, arguments)
                )
                if not isinstance(result, dict):
                    result = _error_response(
                        "upstream_invalid_result",
                        upstream_error={"code": "invalid_result"},
                    )
                upstream_span.set_attribute("mcp.result.is_error", bool(result.get("isError")))
    except GatewayCapacityExceeded:
        if execution_request is not None:
            release_execution_claim(db, execution_request)
            db.commit()
        raise HTTPException(429, "MCP server capacity exceeded") from None
    except GatewayCapacityUnavailable:
        if execution_request is not None:
            release_execution_claim(db, execution_request)
            db.commit()
        raise HTTPException(503, "Gateway capacity coordination unavailable") from None
    # A received response and a successful gateway transaction are different facts.
    # Never release unscanned output or replay the tool to recover persistence.
    outcome_unknown = bool(result.get("upstreamError"))
    with database_http_boundary(tool_execution={
        "state": "outcome_unknown" if outcome_unknown else "response_received",
        "tool_reported_error": None if outcome_unknown else bool(result.get("isError")),
        "result_released": False,
        "automatic_retry_allowed": False,
    }):
        if execution_request is not None:
            execution_request_id = execution_request.id
            policy_decision_id = decision.id
            try:
                mark_execution_result(db, execution_request, result)
            except ExecutionClaimConflict:
                db.rollback()
                record_audit(
                    db,
                    project_id=project_id,
                    action="execution.claim_lost",
                    resource_type="execution_request",
                    resource_id=execution_request_id,
                    actor_type=identity.audit_actor_type,
                    actor_id=identity.agent_id or identity.actor_id,
                    after={"status": "claim_lost", "upstream_result_discarded": True},
                    metadata={"policy_decision_id": policy_decision_id},
                )
                db.commit()
                return _error_response(
                    "execution_claim_lost",
                    execution_request_id=execution_request_id,
                )
        upstream_is_error = bool(result.get("isError"))
        if upstream_is_error:
            record_audit(
                db,
                project_id=project_id,
                action="mcp_tool.upstream_error",
                resource_type="mcp_tool",
                resource_id=f"{server_id}:{tool_name}",
                actor_type=identity.audit_actor_type,
                actor_id=identity.agent_id or identity.actor_id,
                after={"is_error": True},
                metadata={"policy_decision_id": decision.id},
            )
        return scan_tool_result(db, identity, server, tool_name, run_id, revision, result, decision)


def scan_tool_result(
    db: Session, identity: GatewayIdentity, server: McpServer, tool_name: str,
    run_id: str | None, revision: McpToolRevision, result: dict, decision: PolicyDecisionOut,
    *, require_complete_scan: bool = False,
) -> dict:
    """Shared output boundary for live responses and recovered results; never calls a tool."""
    project_id, server_id = identity.project_id, server.id
    text = _result_text(result)
    scan = scan_content(
        ScanRequest(
            project_id=project_id,
            run_id=run_id,
            content=text,
            source="mcp_tool_result",
        ),
        db,
    )
    if require_complete_scan and scan.semantic_assessment is not None and scan.semantic_assessment.status != "ok":
        raise HTTPException(503, "Recovered output scoring is incomplete")
    provenance = _content_provenance(
        db=db,
        project_id=project_id,
        source="mcp_tool_result",
        origin_parts=(server.id, tool_name),
        scan=scan,
    )
    sanitization_changed = scan.sanitized_text != text
    if scan.risk_score >= 0.4 or sanitization_changed:
        post_context = PolicyContext(
            project_id=project_id,
            actor=identity.policy_actor,
            tool={"name": tool_name, "server_id": server_id},
            risk_score=max(scan.risk_score, 0.4 if sanitization_changed else 0.0),
            risk_labels=scan.risk_labels,
            data={
                "labels": scan.risk_labels,
                "content_source": "mcp_tool_result",
                "trust": "untrusted",
            },
            metadata={
                "sanitization_changed": sanitization_changed,
                "content_source": "mcp_tool_result",
                "trust": "untrusted",
            },
        )
        if should_quarantine_external_content(scan):
            if set(scan.risk_labels) & EXTERNAL_CONTENT_QUARANTINE_LABELS:
                evaluated_post = PolicyDecisionOut(
                    action="quarantine",
                    reason_code="external_instruction_override",
                    severity="critical",
                    matched_policy="external_content_boundary",
                    remediation=(
                        "Remove instructions from external content before returning it to the agent."
                    ),
                    context=post_context.model_dump(),
                )
            else:
                evaluated_post = evaluate_builtin_policy(post_context)
        else:
            evaluated_post = evaluate_policy(post_context, db)
        post_decision = persist_policy_decision(db, evaluated_post, post_context)
        if post_decision.action == "allow":
            db.commit()
            return {
                **result,
                "risk": scan.model_dump(),
                "policyDecision": post_decision.model_dump(),
                "provenance": provenance,
            }
        if post_decision.action != "redact":
            db.commit()
            return _error_response(
                post_decision.reason_code,
                policy_decision=post_decision.model_dump(),
                risk=_agent_visible_risk(scan),
                provenance=_with_transformation(provenance, "quarantined"),
            )
        structured_content = result.get("structuredContent")
        if structured_content is not None:
            safe_content = redact_structured_value(result.get("content", []))
            safe_structured_content = redact_structured_value(structured_content)
            safe_payload = json.dumps(
                {
                    "content": safe_content,
                    "structuredContent": safe_structured_content,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            output_schema = revision.descriptor.get("outputSchema")
            schema_valid = True
            if isinstance(output_schema, dict):
                try:
                    validator_class = validator_for(output_schema)
                    validator_class.check_schema(output_schema)
                    schema_valid = validator_class(output_schema).is_valid(
                        safe_structured_content
                    )
                except SchemaError:
                    schema_valid = False
            if (
                scan.risk_score >= 0.4
                or detect_secret_labels(safe_payload)
                or not schema_valid
            ):
                db.commit()
                return _error_response(
                    "structured_output_redaction_unsupported",
                    policy_decision=post_decision.model_dump(),
                    risk=_agent_visible_risk(scan),
                    provenance=_with_transformation(provenance, "quarantined"),
                )
            db.commit()
            return {
                "isError": bool(result.get("isError")),
                "content": safe_content,
                "structuredContent": safe_structured_content,
                "risk": scan.model_dump(),
                "policyDecision": post_decision.model_dump(),
                "provenance": _with_transformation(provenance, "sanitized"),
            }
        db.commit()
        return {
            "content": [{"type": "text", "text": scan.sanitized_text}],
            "risk": scan.model_dump(),
            "policyDecision": post_decision.model_dump(),
            "provenance": _with_transformation(provenance, "sanitized"),
        }
    db.commit()
    return {
        **result,
        "risk": scan.model_dump(),
        "policyDecision": decision.model_dump(),
        "provenance": provenance,
    }


@router.get("/resources/list")
def resources_list(
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, list[Any]]:
    project_id = identity.project_id
    resources: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        if not _server_allows_identity(server, identity):
            continue
        for raw_resource in _load_resources_from_server(server):
            prepared = _scan_resource_descriptor(
                db,
                project_id=project_id,
                raw_descriptor=raw_resource,
                uri_key="uri",
            )
            if prepared is None:
                continue
            resource, scan = prepared
            resources.append(
                {
                    **resource,
                    "serverId": server.id,
                    "riskScore": scan.risk_score,
                    "riskLabels": scan.risk_labels,
                    "provenance": _content_provenance(
                        db=db,
                        project_id=project_id,
                        source="mcp_resource",
                        origin_parts=(server.id, str(resource["uri"])),
                        scan=scan,
                    ),
                }
            )
    db.commit()
    return {"resources": resources}


@router.get("/resources/templates/list")
def resource_templates_list(
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, list[Any]]:
    project_id = identity.project_id
    templates: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        if not _server_allows_identity(server, identity):
            continue
        for raw_template in _load_resource_templates_from_server(server):
            prepared = _scan_resource_descriptor(
                db,
                project_id=project_id,
                raw_descriptor=raw_template,
                uri_key="uriTemplate",
                require_template=True,
            )
            if prepared is None:
                continue
            template, scan = prepared
            templates.append(
                {
                    **template,
                    "serverId": server.id,
                    "riskScore": scan.risk_score,
                    "riskLabels": scan.risk_labels,
                    "provenance": _content_provenance(
                        db=db,
                        project_id=project_id,
                        source="mcp_resource",
                        origin_parts=(server.id, str(template["uriTemplate"])),
                        scan=scan,
                    ),
                }
            )
    db.commit()
    return {"resourceTemplates": templates}


@router.post("/resources/read")
def resources_read(
    payload: dict[str, Any],
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    project_id = identity.project_id
    server_id = payload.get("serverId")
    uri = payload.get("uri")
    if server_id is not None:
        if not isinstance(server_id, str) or not server_id or not isinstance(uri, str) or not uri:
            raise HTTPException(400, "serverId and uri are required")
        if len(uri) > _MAX_RESOURCE_URI_LENGTH:
            raise HTTPException(400, "MCP resource URI is too long")
        credential_labels = set(detect_secret_labels(uri)) - {"email", "phone"}
        if credential_labels:
            raise HTTPException(400, "MCP resource URI contains credential material")
        server = (
            db.query(McpServer)
            .filter(
                McpServer.id == server_id,
                McpServer.project_id == project_id,
                McpServer.status == "active",
            )
            .one_or_none()
        )
        if server is None:
            raise HTTPException(404, "MCP server not found")
        if not _server_allows_identity(server, identity):
            raise HTTPException(404, "MCP resource not found")
        if not _resource_uri_is_advertised(db, server, uri):
            raise HTTPException(404, "MCP resource not found")
        result = strip_untrusted_agentops_metadata(_read_upstream_resource(server, uri))
        if not isinstance(result, dict):
            result = _error_response(
                "upstream_invalid_result",
                upstream_error={"code": "invalid_result"},
            )
        content = _result_text(result)
    else:
        content = payload.get("content", "")
        if not isinstance(content, str):
            raise HTTPException(400, "content must be a string")
        result = {"contents": [{"uri": uri or "inline://resource", "text": content}]}
    scan = scan_content(
        ScanRequest(project_id=project_id, content=content, source="mcp_resource"), db
    )
    provenance = _content_provenance(
        db=db,
        project_id=project_id,
        source="mcp_resource",
        origin_parts=(str(server_id or "inline"), str(uri or "")),
        scan=scan,
    )
    db.commit()
    if should_quarantine_external_content(scan):
        return {
            "isError": True,
            "contents": [],
            "risk": _agent_visible_risk(scan),
            "provenance": _with_transformation(provenance, "quarantined"),
        }
    if scan.sanitized_text != content:
        return {
            "contents": [{"uri": uri or "inline://resource", "text": scan.sanitized_text}],
            "risk": scan.model_dump(),
            "provenance": _with_transformation(provenance, "sanitized"),
        }
    return {
        **result,
        "risk": scan.model_dump(),
        "provenance": provenance,
    }


@router.get("/prompts/list")
def prompts_list(
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, list[Any]]:
    project_id = identity.project_id
    prompts: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        if not _server_allows_identity(server, identity):
            continue
        for raw_prompt in _load_prompts_from_server(server):
            prepared = _scan_prompt_descriptor(
                db,
                project_id=project_id,
                raw_descriptor=raw_prompt,
            )
            if prepared is None:
                continue
            prompt, scan = prepared
            prompts.append(
                {
                    **prompt,
                    "serverId": server.id,
                    "riskScore": scan.risk_score,
                    "riskLabels": scan.risk_labels,
                    "provenance": _content_provenance(
                        db=db,
                        project_id=project_id,
                        source="mcp_prompt",
                        origin_parts=(server.id, str(prompt["name"])),
                        scan=scan,
                    ),
                }
            )
    db.commit()
    return {"prompts": prompts}


@router.post("/prompts/get")
def prompts_get(
    payload: dict[str, Any],
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    project_id = identity.project_id
    server_id = payload.get("serverId")
    name = payload.get("name")
    if server_id is not None:
        arguments = payload.get("arguments", {})
        if (
            not isinstance(server_id, str)
            or not server_id
            or not isinstance(name, str)
            or not name
            or not isinstance(arguments, dict)
            or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in arguments.items()
            )
        ):
            raise HTTPException(400, "serverId, name, and string arguments are required")
        server = (
            db.query(McpServer)
            .filter(
                McpServer.id == server_id,
                McpServer.project_id == project_id,
                McpServer.status == "active",
            )
            .one_or_none()
        )
        if server is None:
            raise HTTPException(404, "MCP server not found")
        if not _server_allows_identity(server, identity):
            raise HTTPException(404, "MCP prompt not found")
        prompt_descriptor = _find_advertised_prompt(db, server, name)
        if prompt_descriptor is None:
            raise HTTPException(404, "MCP prompt not found")
        _validate_prompt_arguments(prompt_descriptor, arguments)
        _reject_unsafe_completion_input(
            db,
            project_id=project_id,
            values=arguments.values(),
            source="mcp_prompt",
            error_detail="MCP prompt arguments were rejected",
        )
        result = strip_untrusted_agentops_metadata(_get_upstream_prompt(server, name, arguments))
        if not isinstance(result, dict):
            result = _error_response(
                "upstream_invalid_result",
                upstream_error={"code": "invalid_result"},
            )
        prompt = _result_text(result)
    else:
        prompt = payload.get("prompt", "")
        if not isinstance(prompt, str):
            raise HTTPException(400, "prompt must be a string")
        result = {"messages": [{"role": "user", "content": {"type": "text", "text": prompt}}]}
    scan = scan_content(ScanRequest(project_id=project_id, content=prompt, source="mcp_prompt"), db)
    provenance = _content_provenance(
        db=db,
        project_id=project_id,
        source="mcp_prompt",
        origin_parts=(str(server_id or "inline"), str(name or "")),
        scan=scan,
    )
    db.commit()
    if should_quarantine_external_content(scan):
        return {
            "isError": True,
            "messages": [],
            "risk": _agent_visible_risk(scan),
            "provenance": _with_transformation(provenance, "quarantined"),
        }
    if scan.sanitized_text != prompt:
        return {
            "messages": [
                {"role": "user", "content": {"type": "text", "text": scan.sanitized_text}}
            ],
            "risk": scan.model_dump(),
            "provenance": _with_transformation(provenance, "sanitized"),
        }
    return {
        **result,
        "risk": scan.model_dump(),
        "provenance": provenance,
    }


@router.post("/completion/complete")
def completion_complete(
    payload: dict[str, Any],
    identity: GatewayIdentity = Depends(require_gateway_read),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    project_id = identity.project_id
    server_id = payload.get("serverId")
    ref_type = payload.get("refType")
    ref_value = payload.get("refValue")
    argument = payload.get("argument")
    context_arguments = payload.get("context", {})
    if (
        not isinstance(server_id, str)
        or not server_id
        or ref_type not in {"prompt", "resource"}
        or not isinstance(ref_value, str)
        or not ref_value
        or not isinstance(argument, dict)
        or set(argument) != {"name", "value"}
        or not isinstance(argument.get("name"), str)
        or not isinstance(argument.get("value"), str)
        or not isinstance(context_arguments, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in context_arguments.items()
        )
    ):
        raise HTTPException(400, "Invalid MCP completion request")
    argument_name = argument["name"]
    argument_value = argument["value"]
    if (
        not argument_name
        or len(argument_name) > _MAX_COMPLETION_NAME_LENGTH
        or len(argument_value) > _MAX_COMPLETION_VALUE_LENGTH
        or len(context_arguments) > _MAX_COMPLETION_ARGUMENTS
        or any(
            not key
            or len(key) > _MAX_COMPLETION_NAME_LENGTH
            or len(value) > _MAX_COMPLETION_VALUE_LENGTH
            for key, value in context_arguments.items()
        )
    ):
        raise HTTPException(400, "Invalid MCP completion request")

    server = (
        db.query(McpServer)
        .filter(
            McpServer.id == server_id,
            McpServer.project_id == project_id,
            McpServer.status == "active",
        )
        .one_or_none()
    )
    if server is None or not _server_allows_identity(server, identity):
        raise HTTPException(404, "MCP completion reference not found")

    if ref_type == "prompt":
        prompt = _find_advertised_prompt(db, server, ref_value)
        if prompt is None:
            raise HTTPException(404, "MCP completion reference not found")
        allowed_names = _prompt_argument_names(prompt)
        content_source = "mcp_prompt"
    else:
        template = _find_advertised_resource_template(db, server, ref_value)
        if template is None:
            raise HTTPException(404, "MCP completion reference not found")
        try:
            allowed_names = set(
                UriTemplate.parse(
                    ref_value,
                    max_length=_MAX_RESOURCE_TEMPLATE_LENGTH,
                    max_variables=_MAX_RESOURCE_TEMPLATE_VARIABLES,
                ).variable_names
            )
        except (InvalidUriTemplate, TypeError, ValueError) as exc:
            raise HTTPException(404, "MCP completion reference not found") from exc
        content_source = "mcp_resource"
    if argument_name not in allowed_names or not set(context_arguments).issubset(allowed_names):
        raise HTTPException(400, "MCP completion argument is not declared")

    _reject_unsafe_completion_input(
        db,
        project_id=project_id,
        values=[argument_value, *context_arguments.values()],
        source=content_source,
        error_detail="MCP completion input was rejected",
    )
    result = strip_untrusted_agentops_metadata(
        _complete_upstream(
            server,
            ref_type=ref_type,
            ref_value=ref_value,
            argument={"name": argument_name, "value": argument_value},
            context_arguments=context_arguments,
        )
    )
    if not isinstance(result, dict):
        raise HTTPException(502, "Upstream returned an invalid MCP completion result")
    completion = result.get("completion")
    if not isinstance(completion, dict):
        raise HTTPException(502, "Upstream returned an invalid MCP completion result")
    values = completion.get("values")
    if (
        not isinstance(values, list)
        or len(values) > _MAX_COMPLETION_VALUES
        or any(not isinstance(value, str) for value in values)
    ):
        raise HTTPException(502, "Upstream returned an invalid MCP completion result")

    safe_values: list[str] = []
    seen: set[str] = set()
    for value in values:
        if len(value) > _MAX_COMPLETION_VALUE_LENGTH:
            raise HTTPException(502, "Upstream returned an invalid MCP completion result")
        if set(detect_secret_labels(value)) - {"email", "phone"}:
            continue
        scan = scan_content(
            ScanRequest(project_id=project_id, content=value, source=content_source),
            db,
        )
        if should_quarantine_external_content(scan):
            continue
        sanitized = scan.sanitized_text
        if sanitized not in seen:
            seen.add(sanitized)
            safe_values.append(sanitized)
    db.commit()
    return {
        "completion": {
            "values": safe_values,
            "total": len(safe_values),
            "hasMore": False,
        }
    }


def load_gateway_config(path: str, db: Session) -> None:
    with open(path, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}
    for name, server_config in (config.get("servers") or {}).items():
        project_id = server_config.get("project_id", "default")
        ensure_project(db, project_id)
        server_id = server_config.get("id") or name
        existing = db.get(McpServer, server_id)
        values = {
            "project_id": project_id,
            "name": name,
            "transport": server_config.get("transport", "stdio"),
            "runtime_provider": server_config.get("runtime_provider", "direct"),
            "command": server_config.get("command"),
            "args": server_config.get("args", []),
            "url": server_config.get("url"),
            "trust_level": server_config.get("trust_level", "external"),
            "allowed_agents": server_config.get("allowed_agents", []),
            "status": "active",
        }
        if existing:
            for key, value in values.items():
                setattr(existing, key, value)
        else:
            db.add(McpServer(id=server_id, **values))
    db.commit()


def create_gateway_app(config_path: str | None = None) -> FastAPI:
    init_db()
    if config_path:
        from agentops_guard.backend.database import SessionLocal

        db = SessionLocal()
        try:
            load_gateway_config(str(config_path), db)
        finally:
            db.close()
    settings = get_settings()
    configure_telemetry("agentops-guard-gateway")
    protocol_server, protocol_app = create_standard_mcp_gateway(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        async with protocol_server.session_manager.run():
            try:
                yield
            finally:
                close_stdio_managers()

    app = FastAPI(
        title="AgentOps Guard MCP Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials="*" not in settings.cors_allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id"],
    )
    app.add_middleware(TelemetryMiddleware, component="gateway")
    app.add_middleware(AuthContextLifecycleMiddleware)
    app.include_router(router)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request, _exc):
        return JSONResponse(status_code=422, content={"detail": "Invalid request"})

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Probes are independent I/O. Serializing them adds their latency and lets
    # overlapping LB/kubelet checks form a queue behind a slow dependency.
    # At most one round runs at a time, with one worker per dependency. A round
    # already in progress may be shared, but a completed result is never cached.
    readiness_limiters = [anyio.CapacityLimiter(1) for _ in range(3)]
    readiness_task = None

    async def check_dependencies():
        return await asyncio.gather(*(
            anyio.to_thread.run_sync(check, limiter=limiter)
            for check, limiter in zip(
                (partial(check_database_ready, engine), semantic_scanner_ready, check_opa_health),
                readiness_limiters, strict=True)
        ), return_exceptions=True)

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        nonlocal readiness_task
        if readiness_task is None or readiness_task.done():
            readiness_task = asyncio.create_task(check_dependencies(), name="gateway-readiness")
        # A disconnected probe waiter must not abandon its still-running DB or
        # HTTP check and release capacity for an accumulating batch of probes.
        results = await asyncio.shield(readiness_task)
        for result in results:
            if isinstance(result, SemanticScannerUnavailable):
                raise HTTPException(503, "Semantic scanner unavailable") from result
            if isinstance(result, OpaUnavailable):
                raise HTTPException(503, "OPA unavailable") from result
            if isinstance(result, BaseException):
                raise result  # Includes real DB failures and programming errors.
        return {"status": "ready"}

    app.mount("/", protocol_app)

    return app


def get_gateway_app() -> FastAPI:
    return create_gateway_app()


def _server_allows_identity(server: McpServer, identity: GatewayIdentity) -> bool:
    allowed_agents = server.allowed_agents or []
    return not allowed_agents or identity.agent_id in allowed_agents


def _scan_resource_descriptor(
    db: Session,
    *,
    project_id: str,
    raw_descriptor: Any,
    uri_key: str,
    require_template: bool = False,
) -> tuple[dict[str, Any], ScanResponse] | None:
    descriptor = strip_untrusted_agentops_metadata(raw_descriptor)
    if not isinstance(descriptor, dict):
        return None
    uri_value = descriptor.get(uri_key)
    if not isinstance(uri_value, str) or not uri_value:
        return None
    maximum_length = _MAX_RESOURCE_TEMPLATE_LENGTH if require_template else _MAX_RESOURCE_URI_LENGTH
    if len(uri_value) > maximum_length:
        return None
    if set(detect_secret_labels(uri_value)) - {"email", "phone"}:
        return None
    if require_template:
        try:
            parsed = UriTemplate.parse(
                uri_value,
                max_length=_MAX_RESOURCE_TEMPLATE_LENGTH,
                max_variables=_MAX_RESOURCE_TEMPLATE_VARIABLES,
            )
        except (InvalidUriTemplate, TypeError, ValueError):
            return None
        if not parsed.variable_names or len(set(parsed.variable_names)) != len(
            parsed.variable_names
        ):
            return None
    scan = scan_content(
        ScanRequest(
            project_id=project_id,
            content=json.dumps(descriptor, ensure_ascii=False, sort_keys=True),
            source="mcp_resource",
        ),
        db,
    )
    if should_quarantine_external_content(scan):
        return None
    return descriptor, scan


def _scan_prompt_descriptor(
    db: Session,
    *,
    project_id: str,
    raw_descriptor: Any,
) -> tuple[dict[str, Any], ScanResponse] | None:
    descriptor = strip_untrusted_agentops_metadata(raw_descriptor)
    if not isinstance(descriptor, dict):
        return None
    name = descriptor.get("name")
    if not isinstance(name, str) or not name or len(name) > _MAX_COMPLETION_NAME_LENGTH:
        return None
    try:
        _prompt_argument_names(descriptor)
    except ValueError:
        return None
    scan = scan_content(
        ScanRequest(
            project_id=project_id,
            content=json.dumps(descriptor, ensure_ascii=False, sort_keys=True),
            source="mcp_prompt",
        ),
        db,
    )
    if should_quarantine_external_content(scan):
        return None
    return descriptor, scan


def _prompt_argument_names(prompt: dict[str, Any]) -> set[str]:
    arguments = prompt.get("arguments")
    if arguments is None:
        return set()
    if not isinstance(arguments, list) or len(arguments) > _MAX_COMPLETION_ARGUMENTS:
        raise ValueError("invalid prompt arguments")
    names: set[str] = set()
    for argument in arguments:
        if not isinstance(argument, dict):
            raise ValueError("invalid prompt argument")
        name = argument.get("name")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > _MAX_COMPLETION_NAME_LENGTH
            or name in names
        ):
            raise ValueError("invalid prompt argument")
        names.add(name)
    return names


def _find_advertised_prompt(
    db: Session,
    server: McpServer,
    name: str,
) -> dict[str, Any] | None:
    for raw_prompt in _load_prompts_from_server(server):
        prepared = _scan_prompt_descriptor(
            db,
            project_id=server.project_id,
            raw_descriptor=raw_prompt,
        )
        if prepared is not None and prepared[0]["name"] == name:
            return prepared[0]
    return None


def _find_advertised_resource_template(
    db: Session,
    server: McpServer,
    uri_template: str,
) -> dict[str, Any] | None:
    for raw_template in _load_resource_templates_from_server(server):
        prepared = _scan_resource_descriptor(
            db,
            project_id=server.project_id,
            raw_descriptor=raw_template,
            uri_key="uriTemplate",
            require_template=True,
        )
        if prepared is not None and prepared[0]["uriTemplate"] == uri_template:
            return prepared[0]
    return None


def _validate_prompt_arguments(prompt: dict[str, Any], arguments: dict[str, str]) -> None:
    try:
        declared_names = _prompt_argument_names(prompt)
    except ValueError as exc:
        raise HTTPException(404, "MCP prompt not found") from exc
    if (
        len(arguments) > _MAX_COMPLETION_ARGUMENTS
        or not set(arguments).issubset(declared_names)
        or any(
            not name
            or len(name) > _MAX_COMPLETION_NAME_LENGTH
            or len(value) > _MAX_COMPLETION_VALUE_LENGTH
            for name, value in arguments.items()
        )
    ):
        raise HTTPException(400, "MCP prompt arguments are invalid")


def _reject_unsafe_completion_input(
    db: Session,
    *,
    project_id: str,
    values: Any,
    source: str,
    error_detail: str,
) -> None:
    for value in values:
        if set(detect_secret_labels(value)) - {"email", "phone"}:
            raise HTTPException(400, error_detail)
        scan = scan_content(
            ScanRequest(project_id=project_id, content=value, source=source),
            db,
        )
        if should_quarantine_external_content(scan):
            raise HTTPException(400, error_detail)


def _resource_uri_is_advertised(db: Session, server: McpServer, uri: str) -> bool:
    for raw_resource in _load_resources_from_server(server):
        prepared = _scan_resource_descriptor(
            db,
            project_id=server.project_id,
            raw_descriptor=raw_resource,
            uri_key="uri",
        )
        if prepared is not None and prepared[0]["uri"] == uri:
            return True
    for raw_template in _load_resource_templates_from_server(server):
        prepared = _scan_resource_descriptor(
            db,
            project_id=server.project_id,
            raw_descriptor=raw_template,
            uri_key="uriTemplate",
            require_template=True,
        )
        if prepared is None:
            continue
        template_value = prepared[0]["uriTemplate"]
        try:
            template = UriTemplate.parse(
                template_value,
                max_length=_MAX_RESOURCE_TEMPLATE_LENGTH,
                max_variables=_MAX_RESOURCE_TEMPLATE_VARIABLES,
            )
            matched = template.match(uri, max_uri_length=_MAX_RESOURCE_URI_LENGTH)
        except (InvalidUriTemplate, TypeError, ValueError):
            continue
        if matched is None or any(not isinstance(value, str) for value in matched.values()):
            continue
        required = set(template.variable_names) - set(template.query_variable_names)
        if required.issubset(matched) and template.expand(matched) == uri:
            return True
    return False


def _load_tools_from_server(server: McpServer, strict: bool = False) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        try:
            return StreamableHttpTransport(
                server.url, timeout=settings.gateway_call_timeout_seconds
            ).list_tools()
        except httpx.HTTPError:
            if strict:
                raise
            return []
    if server.transport == "legacy_http" and server.url:
        try:
            return LegacyHttpTransport(
                server.url, timeout=settings.gateway_call_timeout_seconds
            ).list_tools()
        except httpx.HTTPError:
            if strict:
                raise
            return []
    if server.transport == "stdio" and server.command:
        try:
            manager = get_stdio_manager(
                server.id,
                server.command,
                server.args or [],
                timeout=settings.gateway_call_timeout_seconds,
                max_response_bytes=settings.gateway_max_response_bytes,
                max_stderr_bytes=settings.gateway_max_stderr_bytes,
            )
            return _stdio_list_all(
                manager,
                method="tools/list",
                result_key="tools",
            )
        except (AttributeError, OSError, RuntimeError):
            if strict:
                raise
            return []
    return [
        {
            "name": f"{server.name}.echo",
            "description": f"Demo echo tool proxied from {server.name}.",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
            "annotations": {"trustLevel": server.trust_level},
        }
    ]


def _call_upstream_tool(
    server: McpServer, tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        try:
            return StreamableHttpTransport(
                server.url, timeout=settings.gateway_call_timeout_seconds
            ).call_tool(tool_name, arguments)
        except UpstreamTransportError as exc:
            return _error_response("upstream_http_error", upstream_error={"code": exc.code})
        except httpx.HTTPError:
            return _error_response("upstream_http_error", upstream_error={"code": "http_error"})
    if server.transport == "legacy_http" and server.url:
        try:
            return LegacyHttpTransport(
                server.url, timeout=settings.gateway_call_timeout_seconds
            ).call_tool(tool_name, arguments)
        except UpstreamTransportError as exc:
            return _error_response("upstream_http_error", upstream_error={"code": exc.code})
        except httpx.HTTPError:
            return _error_response("upstream_http_error", upstream_error={"code": "http_error"})
    if server.transport == "stdio" and server.command:
        try:
            response = get_stdio_manager(
                server.id,
                server.command,
                server.args or [],
                timeout=settings.gateway_call_timeout_seconds,
                max_response_bytes=settings.gateway_max_response_bytes,
                max_stderr_bytes=settings.gateway_max_stderr_bytes,
            ).request("tools/call", {"name": tool_name, "arguments": arguments})
            if "error" in response:
                code = safe_stdio_error_code(response["error"])
                return _error_response(
                    "upstream_stdio_error",
                    upstream_error={"code": code},
                )
            return response.get("result", {})
        except (OSError, TimeoutError, ValueError):
            return _error_response("upstream_stdio_error", upstream_error={"code": "stdio_error"})
    return {"content": [{"type": "text", "text": str(arguments.get("text", arguments))}]}


def _load_resources_from_server(server: McpServer) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).list_resources()
    if server.transport == "stdio" and server.command:
        manager = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        )
        return _stdio_list_all(
            manager,
            method="resources/list",
            result_key="resources",
        )
    return []


def _load_resource_templates_from_server(server: McpServer) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).list_resource_templates()
    if server.transport == "stdio" and server.command:
        manager = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        )
        return _stdio_list_all(
            manager,
            method="resources/templates/list",
            result_key="resourceTemplates",
            method_not_found_is_empty=True,
        )
    return []


def _read_upstream_resource(server: McpServer, uri: str) -> dict[str, Any]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).read_resource(uri)
    if server.transport == "stdio" and server.command:
        response = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        ).request("resources/read", {"uri": uri})
        if "error" in response:
            return _error_response(
                "upstream_stdio_error",
                upstream_error={"code": safe_stdio_error_code(response["error"])},
            )
        return response.get("result", {})
    return _error_response("MCP resources are not supported by this transport")


def _load_prompts_from_server(server: McpServer) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).list_prompts()
    if server.transport == "stdio" and server.command:
        manager = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        )
        return _stdio_list_all(
            manager,
            method="prompts/list",
            result_key="prompts",
        )
    return []


def _stdio_list_all(
    manager: Any,
    *,
    method: str,
    result_key: str,
    method_not_found_is_empty: bool = False,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(_MAX_STDIO_LIST_PAGES):
        params = {} if cursor is None else {"cursor": cursor}
        response = manager.request(method, params)
        if not isinstance(response, dict):
            raise RuntimeError("MCP stdio list request failed")
        if "error" in response:
            error = response.get("error")
            if (
                method_not_found_is_empty
                and isinstance(error, dict)
                and error.get("code") == -32601
            ):
                return []
            raise RuntimeError("MCP stdio list request failed")
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("MCP stdio list result is invalid")
        page = result.get(result_key)
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise RuntimeError("MCP stdio list page is invalid")
        items.extend(page)
        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            return items
        if (
            not isinstance(next_cursor, str)
            or not next_cursor
            or len(next_cursor) > 512
            or next_cursor in seen_cursors
        ):
            raise RuntimeError("MCP stdio pagination cursor is invalid")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise RuntimeError("MCP stdio pagination exceeded its page limit")


def _get_upstream_prompt(server: McpServer, name: str, arguments: dict[str, str]) -> dict[str, Any]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).get_prompt(name, arguments)
    if server.transport == "stdio" and server.command:
        response = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        ).request("prompts/get", {"name": name, "arguments": arguments})
        if "error" in response:
            return _error_response(
                "upstream_stdio_error",
                upstream_error={"code": safe_stdio_error_code(response["error"])},
            )
        return response.get("result", {})
    return _error_response("MCP prompts are not supported by this transport")


def _complete_upstream(
    server: McpServer,
    *,
    ref_type: str,
    ref_value: str,
    argument: dict[str, str],
    context_arguments: dict[str, str],
) -> dict[str, Any]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).complete(ref_type, ref_value, argument, context_arguments)
    if server.transport == "stdio" and server.command:
        reference = (
            {"type": "ref/prompt", "name": ref_value}
            if ref_type == "prompt"
            else {"type": "ref/resource", "uri": ref_value}
        )
        params: dict[str, Any] = {"ref": reference, "argument": argument}
        if context_arguments:
            params["context"] = {"arguments": context_arguments}
        response = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        ).request("completion/complete", params)
        if "error" in response:
            error = response.get("error")
            if isinstance(error, dict) and error.get("code") == -32601:
                return {"completion": {"values": []}}
            return _error_response(
                "upstream_stdio_error",
                upstream_error={"code": safe_stdio_error_code(error)},
            )
        return response.get("result", {})
    return {"completion": {"values": []}}


def _error_response(
    message: str,
    *,
    policy_decision: dict[str, Any] | None = None,
    risk: dict[str, Any] | None = None,
    upstream_error: dict[str, Any] | None = None,
    approval_request_id: str | None = None,
    execution_request_id: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = {
        "isError": True,
        "content": [{"type": "text", "text": message}],
        "policyDecision": policy_decision,
        "risk": risk,
        "upstreamError": upstream_error,
        "approvalRequestId": approval_request_id,
        "executionRequestId": execution_request_id,
    }
    if provenance is not None:
        response["provenance"] = provenance
    return response


def _content_provenance(
    *,
    db: Session,
    project_id: str,
    source: str,
    origin_parts: tuple[str, ...],
    scan: ScanResponse,
) -> dict[str, Any]:
    provenance = build_content_provenance(
        project_id=project_id,
        source=source,
        origin_parts=origin_parts,
        content_ref=scan.sanitized_content_ref,
    )
    if scan.sanitized_content_ref is not None:
        content = db.get(ContentObject, scan.sanitized_content_ref)
        if content is not None and content.project_id == project_id:
            content.metadata_json = {
                **(content.metadata_json or {}),
                "content_provenance": provenance,
            }
    return provenance


def _with_transformation(provenance: dict[str, Any], transformation: str) -> dict[str, Any]:
    transformations = list(provenance.get("transformations") or [])
    if transformation not in transformations:
        transformations.append(transformation)
    result = {**provenance, "transformations": transformations}
    if transformation == "quarantined":
        result.pop("contentRef", None)
    return result


def _result_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts: list[str] = []
        for key in sorted(value):
            parts.extend((str(key), _result_text(value[key])))
        return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(_result_text(item) for item in value)
    return str(value)


def _agent_visible_risk(scan: ScanResponse) -> dict[str, Any]:
    if not should_quarantine_external_content(scan):
        return scan.model_dump()
    return scan.model_copy(
        update={
            "evidence_spans": [],
            "sanitized_content_ref": None,
            "sanitized_text": "",
        }
    ).model_dump()


app = get_gateway_app()
