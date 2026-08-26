from __future__ import annotations

import json
from typing import Any

import httpx
import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from opentelemetry import trace

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db, init_db
from agentops_guard.backend.models import ApprovalRequest, McpServer, McpTool, Run
from agentops_guard.backend.schemas import (
    PolicyContext,
    PolicyDecisionOut,
    ScanRequest,
    ScanResponse,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.policy import (
    INTENT_MANIFEST_KEY,
    assess_tool_action_alignment,
    evaluate_builtin_policy,
    evaluate_policy,
    persist_policy_decision,
)
from agentops_guard.backend.services.opa import OpaUnavailable, check_opa_health
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.scanner import (
    EXTERNAL_CONTENT_QUARANTINE_LABELS,
    scan_content,
    should_quarantine_external_content,
)
from agentops_guard.backend.services.semantic_scanner import semantic_scanner_ready
from agentops_guard.backend.telemetry import TelemetryMiddleware, configure_telemetry
from agentops_guard.gateway.transports import LegacyHttpTransport, StreamableHttpTransport
from agentops_guard.gateway.transports.stdio import get_stdio_manager

router = APIRouter(prefix="/mcp")


@router.get("/tools/list")
def tools_list(project_id: str = "default", db: Session = Depends(get_db)) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        upstream_tools = _load_tools_from_server(server)
        for tool in upstream_tools:
            description = tool.get("description") or ""
            input_schema = tool.get("inputSchema", {})
            annotations = tool.get("annotations", {})
            scan = scan_content(
                ScanRequest(
                    project_id=project_id,
                    content=json.dumps(tool, ensure_ascii=False, sort_keys=True),
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
                existing.description = visible_description
                existing.input_schema = visible_input_schema
                existing.annotations = visible_annotations
                existing.risk_score = scan.risk_score
                existing.risk_labels = scan.risk_labels
                existing.status = status
            else:
                db.add(
                    McpTool(
                        id=tool_id,
                        project_id=project_id,
                        server_id=server.id,
                        name=tool.get("name", "unknown"),
                        description=visible_description,
                        input_schema=visible_input_schema,
                        annotations=visible_annotations,
                        risk_score=scan.risk_score,
                        risk_labels=scan.risk_labels,
                        status=status,
                    )
                )
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
                    }
                )
    db.commit()
    return {"tools": tools}


@router.post("/tools/call")
def tools_call(
    payload: dict[str, Any], project_id: str = "default", db: Session = Depends(get_db)
) -> dict[str, Any]:
    tool_name = payload.get("name")
    server_id = payload.get("serverId")
    arguments = payload.get("arguments", {})
    run_id = payload.get("runId")
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
    intent_manifest = None
    if run_id is not None:
        run = db.query(Run).filter(Run.id == run_id, Run.project_id == project_id).one_or_none()
        if run is None or (run.agent_id and run.agent_id != payload.get("agentId")):
            raise HTTPException(404, "Run not found")
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
    argument_scan = scan_content(
        ScanRequest(
            project_id=project_id,
            content=json.dumps(arguments, ensure_ascii=False, sort_keys=True),
            source="mcp_tool_arguments",
        ),
        db,
    )
    context = PolicyContext(
        project_id=project_id,
        run_id=run_id,
        actor={"agent_id": payload.get("agentId")},
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
        },
        metadata={
            "content_source": "mcp_tool_arguments",
            "trust": "agent_generated",
            "original_intent_source": "run.input_ref" if run_id else None,
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
    decision = persist_policy_decision(db, evaluated, audit_context)
    approval_request_id = None
    if decision.action == "require_approval":
        approval_request_id = (
            db.query(ApprovalRequest.id).filter(ApprovalRequest.decision_id == decision.id).scalar()
        )
    if decision.action != "allow":
        db.commit()
        return _error_response(
            decision.reason_code,
            policy_decision=decision.model_dump(),
            risk=argument_scan.model_dump(),
            approval_request_id=approval_request_id,
        )
    db.commit()
    with trace.get_tracer("agentops_guard.gateway").start_as_current_span(
        "mcp.tool.call",
        attributes={
            "mcp.transport": server.transport,
            "mcp.runtime_provider": server.runtime_provider,
        },
    ) as upstream_span:
        result = _call_upstream_tool(server, tool_name, arguments)
        upstream_span.set_attribute("mcp.result.is_error", bool(result.get("isError")))
    upstream_is_error = bool(result.get("isError"))
    if upstream_is_error:
        record_audit(
            db,
            project_id=project_id,
            action="mcp_tool.upstream_error",
            resource_type="mcp_tool",
            resource_id=f"{server_id}:{tool_name}",
            actor_type="agent",
            actor_id=payload.get("agentId"),
            after={"is_error": True},
            metadata={"policy_decision_id": decision.id},
        )
    text = _result_text(result)
    scan = scan_content(
        ScanRequest(project_id=project_id, content=text, source="mcp_tool_result"), db
    )
    sanitization_changed = scan.sanitized_text != text
    if scan.risk_score >= 0.4 or sanitization_changed:
        post_context = PolicyContext(
            project_id=project_id,
            actor={"agent_id": payload.get("agentId")},
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
            }
        if post_decision.action != "redact":
            db.commit()
            return _error_response(
                post_decision.reason_code,
                policy_decision=post_decision.model_dump(),
                risk=_agent_visible_risk(scan),
            )
        db.commit()
        return {
            "content": [{"type": "text", "text": scan.sanitized_text}],
            "risk": scan.model_dump(),
            "policyDecision": post_decision.model_dump(),
        }
    db.commit()
    return {**result, "risk": scan.model_dump(), "policyDecision": decision.model_dump()}


@router.get("/resources/list")
def resources_list(
    project_id: str = "default", db: Session = Depends(get_db)
) -> dict[str, list[Any]]:
    resources: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        for resource in _load_resources_from_server(server):
            scan = scan_content(
                ScanRequest(
                    project_id=project_id,
                    content=json.dumps(resource, ensure_ascii=False, sort_keys=True),
                    source="mcp_resource",
                ),
                db,
            )
            if not should_quarantine_external_content(scan):
                resources.append(
                    {
                        **resource,
                        "serverId": server.id,
                        "riskScore": scan.risk_score,
                        "riskLabels": scan.risk_labels,
                    }
                )
    db.commit()
    return {"resources": resources}


@router.post("/resources/read")
def resources_read(
    payload: dict[str, Any], project_id: str = "default", db: Session = Depends(get_db)
) -> dict[str, Any]:
    server_id = payload.get("serverId")
    uri = payload.get("uri")
    if server_id is not None:
        if not isinstance(server_id, str) or not server_id or not isinstance(uri, str) or not uri:
            raise HTTPException(400, "serverId and uri are required")
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
        result = _read_upstream_resource(server, uri)
        content = _result_text(result)
    else:
        content = payload.get("content", "")
        if not isinstance(content, str):
            raise HTTPException(400, "content must be a string")
        result = {"contents": [{"uri": uri or "inline://resource", "text": content}]}
    scan = scan_content(
        ScanRequest(project_id=project_id, content=content, source="mcp_resource"), db
    )
    db.commit()
    if should_quarantine_external_content(scan):
        return {
            "isError": True,
            "contents": [],
            "risk": _agent_visible_risk(scan),
        }
    if scan.sanitized_text != content:
        return {
            "contents": [{"uri": uri or "inline://resource", "text": scan.sanitized_text}],
            "risk": scan.model_dump(),
        }
    return {
        **result,
        "risk": scan.model_dump(),
    }


@router.get("/prompts/list")
def prompts_list(
    project_id: str = "default", db: Session = Depends(get_db)
) -> dict[str, list[Any]]:
    prompts: list[dict[str, Any]] = []
    servers = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id, McpServer.status == "active")
        .all()
    )
    for server in servers:
        for prompt in _load_prompts_from_server(server):
            scan = scan_content(
                ScanRequest(
                    project_id=project_id,
                    content=json.dumps(prompt, ensure_ascii=False, sort_keys=True),
                    source="mcp_prompt",
                ),
                db,
            )
            if not should_quarantine_external_content(scan):
                prompts.append(
                    {
                        **prompt,
                        "serverId": server.id,
                        "riskScore": scan.risk_score,
                        "riskLabels": scan.risk_labels,
                    }
                )
    db.commit()
    return {"prompts": prompts}


@router.post("/prompts/get")
def prompts_get(
    payload: dict[str, Any], project_id: str = "default", db: Session = Depends(get_db)
) -> dict[str, Any]:
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
                isinstance(key, str) and isinstance(value, str)
                for key, value in arguments.items()
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
        result = _get_upstream_prompt(server, name, arguments)
        prompt = _result_text(result)
    else:
        prompt = payload.get("prompt", "")
        if not isinstance(prompt, str):
            raise HTTPException(400, "prompt must be a string")
        result = {
            "messages": [{"role": "user", "content": {"type": "text", "text": prompt}}]
        }
    scan = scan_content(
        ScanRequest(project_id=project_id, content=prompt, source="mcp_prompt"), db
    )
    db.commit()
    if should_quarantine_external_content(scan):
        return {
            "isError": True,
            "messages": [],
            "risk": _agent_visible_risk(scan),
        }
    if scan.sanitized_text != prompt:
        return {
            "messages": [
                {"role": "user", "content": {"type": "text", "text": scan.sanitized_text}}
            ],
            "risk": scan.model_dump(),
        }
    return {
        **result,
        "risk": scan.model_dump(),
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
    app = FastAPI(title="AgentOps Guard MCP Gateway", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials="*" not in settings.cors_allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(TelemetryMiddleware, component="gateway")
    app.include_router(router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        semantic_scanner_ready()
        try:
            check_opa_health()
        except OpaUnavailable as exc:
            raise HTTPException(503, "OPA unavailable") from exc
        return {"status": "ready"}

    return app


def get_gateway_app() -> FastAPI:
    return create_gateway_app()


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
            response = get_stdio_manager(
                server.id,
                server.command,
                server.args or [],
                timeout=settings.gateway_call_timeout_seconds,
                max_response_bytes=settings.gateway_max_response_bytes,
                max_stderr_bytes=settings.gateway_max_stderr_bytes,
            ).request("tools/list", {})
            if strict and "error" in response:
                raise RuntimeError(str(response["error"]))
            return response.get("result", {}).get("tools", [])
        except Exception:
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
                server.url, timeout=max(settings.gateway_call_timeout_seconds, 30.0)
            ).call_tool(tool_name, arguments)
        except httpx.HTTPError as exc:
            return _error_response(
                str(exc), upstream_error={"code": "http_error", "message": str(exc)}
            )
    if server.transport == "legacy_http" and server.url:
        try:
            return LegacyHttpTransport(
                server.url, timeout=max(settings.gateway_call_timeout_seconds, 30.0)
            ).call_tool(tool_name, arguments)
        except httpx.HTTPError as exc:
            return _error_response(
                str(exc), upstream_error={"code": "http_error", "message": str(exc)}
            )
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
                return _error_response(str(response["error"]), upstream_error=response["error"])
            return response.get("result", {})
        except Exception as exc:
            return _error_response(
                str(exc), upstream_error={"code": "stdio_error", "message": str(exc)}
            )
    return {"content": [{"type": "text", "text": str(arguments.get("text", arguments))}]}


def _load_resources_from_server(server: McpServer) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).list_resources()
    if server.transport == "stdio" and server.command:
        response = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        ).request("resources/list", {})
        return response.get("result", {}).get("resources", [])
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
            return _error_response(str(response["error"]), upstream_error=response["error"])
        return response.get("result", {})
    return _error_response("MCP resources are not supported by this transport")


def _load_prompts_from_server(server: McpServer) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        return StreamableHttpTransport(
            server.url, timeout=settings.gateway_call_timeout_seconds
        ).list_prompts()
    if server.transport == "stdio" and server.command:
        response = get_stdio_manager(
            server.id,
            server.command,
            server.args or [],
            timeout=settings.gateway_call_timeout_seconds,
            max_response_bytes=settings.gateway_max_response_bytes,
            max_stderr_bytes=settings.gateway_max_stderr_bytes,
        ).request("prompts/list", {})
        return response.get("result", {}).get("prompts", [])
    return []


def _get_upstream_prompt(
    server: McpServer, name: str, arguments: dict[str, str]
) -> dict[str, Any]:
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
            return _error_response(str(response["error"]), upstream_error=response["error"])
        return response.get("result", {})
    return _error_response("MCP prompts are not supported by this transport")


def _error_response(
    message: str,
    *,
    policy_decision: dict[str, Any] | None = None,
    risk: dict[str, Any] | None = None,
    upstream_error: dict[str, Any] | None = None,
    approval_request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": message}],
        "policyDecision": policy_decision,
        "risk": risk,
        "upstreamError": upstream_error,
        "approvalRequestId": approval_request_id,
    }


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
