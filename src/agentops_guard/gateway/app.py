from __future__ import annotations

import json
from typing import Any

import httpx
import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.database import get_db, init_db
from agentops_guard.backend.models import ApprovalRequest, McpServer, McpTool
from agentops_guard.backend.schemas import PolicyContext, ScanRequest
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.policy import evaluate_policy, persist_policy_decision
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.scanner import scan_content
from agentops_guard.gateway.transports import StreamableHttpTransport
from agentops_guard.gateway.transports.stdio import get_stdio_manager

router = APIRouter(prefix="/mcp")


@router.get("/tools/list")
def tools_list(project_id: str = "default", db: Session = Depends(get_db)) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    servers = db.query(McpServer).filter(McpServer.project_id == project_id, McpServer.status == "active").all()
    for server in servers:
        upstream_tools = _load_tools_from_server(server)
        for tool in upstream_tools:
            description = tool.get("description") or ""
            scan = scan_content(ScanRequest(project_id=project_id, content=description, source="mcp_tool_description"))
            status = "quarantined" if scan.risk_score >= 0.7 else "active"
            tool_id = f"{server.id}:{tool.get('name')}"
            existing = db.get(McpTool, tool_id)
            if existing:
                existing.description = description
                existing.input_schema = tool.get("inputSchema", {})
                existing.annotations = tool.get("annotations", {})
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
                        description=description,
                        input_schema=tool.get("inputSchema", {}),
                        annotations=tool.get("annotations", {}),
                        risk_score=scan.risk_score,
                        risk_labels=scan.risk_labels,
                        status=status,
                    )
                )
            tools.append({**tool, "serverId": server.id, "riskScore": scan.risk_score, "riskLabels": scan.risk_labels, "status": status})
    db.commit()
    return {"tools": tools}


@router.post("/tools/call")
def tools_call(payload: dict[str, Any], project_id: str = "default", db: Session = Depends(get_db)) -> dict[str, Any]:
    tool_name = payload.get("name")
    server_id = payload.get("serverId")
    arguments = payload.get("arguments", {})
    if not tool_name or not server_id:
        raise HTTPException(400, "name and serverId are required")
    if not isinstance(arguments, dict):
        raise HTTPException(400, "arguments must be an object")
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
        actor={"agent_id": payload.get("agentId")},
        tool={
            "name": tool_name,
            "server_id": server_id,
            "status": tool.status if tool else "active",
            "allowed_agents": server.allowed_agents or [],
            "args": arguments,
        },
        risk_score=argument_scan.risk_score,
        risk_labels=argument_scan.risk_labels,
        data={"labels": argument_scan.risk_labels},
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
            db.query(ApprovalRequest.id)
            .filter(ApprovalRequest.decision_id == decision.id)
            .scalar()
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
    result = _call_upstream_tool(server, tool_name, arguments)
    if result.get("isError"):
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
        db.commit()
        return {
            **result,
            "policyDecision": decision.model_dump(),
            "risk": argument_scan.model_dump(),
        }
    text = _result_text(result)
    scan = scan_content(ScanRequest(project_id=project_id, content=text, source="mcp_tool_result"), db)
    sanitization_changed = scan.sanitized_text != text
    if scan.risk_score >= 0.4 or sanitization_changed:
        post_context = PolicyContext(
            project_id=project_id,
            actor={"agent_id": payload.get("agentId")},
            tool={"name": tool_name, "server_id": server_id},
            risk_score=max(scan.risk_score, 0.4 if sanitization_changed else 0.0),
            risk_labels=scan.risk_labels,
            data={"labels": scan.risk_labels},
            metadata={"sanitization_changed": sanitization_changed},
        )
        post_decision = persist_policy_decision(
            db,
            evaluate_policy(post_context, db),
            post_context,
        )
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
                risk=scan.model_dump(),
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
def resources_list() -> dict[str, list[Any]]:
    return {"resources": []}


@router.post("/resources/read")
def resources_read(payload: dict[str, Any], project_id: str = "default", db: Session = Depends(get_db)) -> dict[str, Any]:
    content = payload.get("content", "")
    scan = scan_content(ScanRequest(project_id=project_id, content=content, source="mcp_resource"), db)
    db.commit()
    return {"contents": [{"uri": payload.get("uri", "inline://resource"), "text": scan.sanitized_text}], "risk": scan.model_dump()}


@router.get("/prompts/list")
def prompts_list() -> dict[str, list[Any]]:
    return {"prompts": []}


@router.post("/prompts/get")
def prompts_get(payload: dict[str, Any], project_id: str = "default", db: Session = Depends(get_db)) -> dict[str, Any]:
    prompt = payload.get("prompt", "")
    scan = scan_content(ScanRequest(project_id=project_id, content=prompt, source="mcp_prompt"), db)
    db.commit()
    return {"messages": [{"role": "user", "content": {"type": "text", "text": scan.sanitized_text}}], "risk": scan.model_dump()}


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
    app = FastAPI(title="AgentOps Guard MCP Gateway", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials="*" not in settings.cors_allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


def get_gateway_app() -> FastAPI:
    return create_gateway_app()


def _load_tools_from_server(server: McpServer, strict: bool = False) -> list[dict[str, Any]]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        try:
            return StreamableHttpTransport(server.url, timeout=settings.gateway_call_timeout_seconds).list_tools()
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


def _call_upstream_tool(server: McpServer, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    if server.transport == "streamable_http" and server.url:
        try:
            return StreamableHttpTransport(server.url, timeout=max(settings.gateway_call_timeout_seconds, 30.0)).call_tool(tool_name, arguments)
        except httpx.HTTPError as exc:
            return _error_response(str(exc), upstream_error={"code": "http_error", "message": str(exc)})
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
            return _error_response(str(exc), upstream_error={"code": "stdio_error", "message": str(exc)})
    return {"content": [{"type": "text", "text": str(arguments.get("text", arguments))}]}


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


def _result_text(result: dict[str, Any]) -> str:
    content = result.get("content", [])
    texts = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            texts.append(str(item.get("text", "")))
    return "\n".join(texts) or str(result)


app = get_gateway_app()
