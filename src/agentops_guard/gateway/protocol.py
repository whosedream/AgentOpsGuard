from __future__ import annotations

import base64
import binascii
from functools import partial
import hmac
import importlib
import json
from typing import Any
from urllib.parse import urlsplit

import anyio
from fastapi import HTTPException
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.uri_template import InvalidUriTemplate, UriTemplate
from mcp.shared.exceptions import MCPError
from pydantic import TypeAdapter, ValidationError
from sqlalchemy.orm import Session
from starlette.applications import Starlette

from agentops_guard.backend.auth import authenticate_bearer_token
from agentops_guard.backend.config import Settings
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.database_resilience import PostToolDatabaseUnavailable, database_http_boundary
from agentops_guard.backend.services.content_provenance import (
    strip_untrusted_agentops_metadata,
)
from agentops_guard.backend.services.mcp_tool_revisions import content_digest
from agentops_guard.gateway.auth import GatewayIdentity


AGENTOPS_REQUEST_META = "io.agentops/request"
_CONTENT_ADAPTER = TypeAdapter(types.ContentBlock)
_RESOURCE_CONTENT_ADAPTER = TypeAdapter(types.TextResourceContents | types.BlobResourceContents)
_PROMPT_MESSAGE_ADAPTER = TypeAdapter(types.PromptMessage)
_MAX_RESOURCE_TEMPLATE_LENGTH = 4_096
_MAX_RESOURCE_TEMPLATE_VARIABLES = 32
_MAX_PROTECTED_RESOURCE_URI_LENGTH = 8_192


class AgentOpsTokenVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def verify_token(self, token: str) -> AccessToken | None:
        def verify() -> AccessToken | None:
            db = SessionLocal()
            try:
                context = authenticate_bearer_token(db, token)
                if context is None:
                    db.rollback()
                    return None
                db.commit()
                project_id = context.project_id
                if context.is_operator and project_id is None:
                    project_id = "default"
                if project_id is None or context.actor_id is None:
                    return None
                scopes = sorted(set(context.scopes) | set(context.capabilities))
                claims: dict[str, Any] = {
                    "auth_kind": context.kind,
                    "project_id": project_id,
                    "actor_id": context.actor_id,
                }
                if context.agent_id is not None:
                    claims["agent_id"] = context.agent_id
                if context.active_role is not None:
                    claims["role"] = context.active_role
                if self.settings.oidc_issuer and context.kind in {
                    "oidc_user",
                    "workload_token",
                }:
                    claims["iss"] = self.settings.oidc_issuer
                return AccessToken(
                    token=token,
                    client_id=context.key_id or context.actor_id,
                    scopes=scopes,
                    resource=self.settings.mcp_public_url,
                    subject=context.actor_id,
                    claims=claims,
                )
            finally:
                db.close()

        with database_http_boundary():
            return await anyio.to_thread.run_sync(verify)


def create_standard_mcp_gateway(settings: Settings) -> tuple[Server[Any], Starlette]:
    cursor_key = hmac.digest(
        settings.api_key.encode("utf-8"),
        b"agentops-mcp-pagination-v1",
        "sha256",
    )
    server: Server[Any] = Server(
        "AgentOps Guard",
        version="0.1.0",
        instructions=(
            "Tools, resources, and prompts are filtered through AgentOps Guard authorization, "
            "scanning, approval, and audit controls."
        ),
        on_list_tools=partial(
            _list_tools,
            page_size=settings.mcp_page_size,
            cursor_key=cursor_key,
        ),
        on_call_tool=_call_tool,
        on_list_resources=partial(
            _list_resources,
            page_size=settings.mcp_page_size,
            cursor_key=cursor_key,
        ),
        on_list_resource_templates=partial(
            _list_resource_templates,
            page_size=settings.mcp_page_size,
            cursor_key=cursor_key,
        ),
        on_read_resource=_read_resource,
        on_list_prompts=partial(
            _list_prompts,
            page_size=settings.mcp_page_size,
            cursor_key=cursor_key,
        ),
        on_get_prompt=_get_prompt,
        on_completion=_complete,
    )
    public = urlsplit(settings.mcp_public_url)
    issuer = settings.oidc_issuer or f"{public.scheme}://{public.netloc}"
    auth = AuthSettings(
        issuer_url=issuer,
        resource_server_url=settings.mcp_public_url if settings.oidc_issuer else None,
        required_scopes=[],
    )
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=settings.mcp_allowed_hosts,
        allowed_origins=settings.mcp_allowed_origins,
    )
    protocol_app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        auth=auth,
        token_verifier=AgentOpsTokenVerifier(settings),
        transport_security=security,
    )
    return server, protocol_app


async def _list_tools(
    _context: ServerRequestContext[Any],
    params: types.PaginatedRequestParams | None,
    *,
    page_size: int,
    cursor_key: bytes,
) -> types.ListToolsResult:
    identity = _require_identity("mcp:read")
    result = await _call_gateway("tools_list", identity=identity)
    tools: list[types.Tool] = []
    for item in result.get("tools", []):
        server_id = _required_string(item, "serverId")
        upstream_name = _required_string(item, "name")
        annotations = None
        raw_annotations = item.get("annotations")
        if isinstance(raw_annotations, dict):
            try:
                annotations = types.ToolAnnotations.model_validate(raw_annotations)
            except ValidationError:
                annotations = None
        input_schema = item.get("inputSchema")
        if not isinstance(input_schema, dict):
            input_schema = {"type": "object", "properties": {}}
        output_schema = item.get("outputSchema")
        tools.append(
            types.Tool(
                name=_stable_name("tool", identity.project_id, server_id, upstream_name),
                title=str(item.get("title") or f"{server_id}: {upstream_name}"),
                description=str(item.get("description") or ""),
                inputSchema=input_schema,
                outputSchema=output_schema if isinstance(output_schema, dict) else None,
                annotations=annotations,
                _meta={
                    "io.agentops/source": {
                        "serverId": server_id,
                        "revisionId": item.get("revisionId"),
                        "riskScore": item.get("riskScore"),
                        "riskLabels": item.get("riskLabels") or [],
                    },
                    "io.agentops/provenance": item.get("provenance"),
                },
            )
        )
    tools.sort(key=lambda item: item.name)
    page, next_cursor = _paginate(
        tools,
        params,
        kind="tools",
        identity=identity,
        page_size=page_size,
        cursor_key=cursor_key,
    )
    return types.ListToolsResult(tools=page, next_cursor=next_cursor)


async def _call_tool(
    _context: ServerRequestContext[Any],
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    identity = _require_identity("mcp:invoke")
    listed = await _call_gateway("tools_list", identity=identity)
    source = _find_named_source(
        "tool",
        identity.project_id,
        params.name,
        listed.get("tools", []),
    )
    request_metadata = _request_metadata(params.meta)
    payload: dict[str, Any] = {
        "serverId": _required_string(source, "serverId"),
        "name": _required_string(source, "name"),
        "arguments": params.arguments or {},
    }
    payload.update(request_metadata)
    result = await _call_gateway("tools_call", payload=payload, identity=identity)
    content: list[types.ContentBlock] = []
    try:
        content = [
            _CONTENT_ADAPTER.validate_python(strip_untrusted_agentops_metadata(block))
            for block in result.get("content", [])
            if isinstance(block, dict)
        ]
    except ValidationError as exc:
        raise MCPError(-32000, "Upstream returned unsupported content") from exc
    if not content:
        content = [types.TextContent(text="empty_result")]
    control = {
        key: result.get(key)
        for key in (
            "policyDecision",
            "risk",
            "upstreamError",
            "approvalRequestId",
            "executionRequestId",
            "invocation",
        )
        if result.get(key) is not None
    }
    metadata: dict[str, Any] = {}
    if control:
        metadata["io.agentops/control"] = control
    provenance = result.get("provenance")
    if isinstance(provenance, dict):
        metadata["io.agentops/provenance"] = provenance
    structured = strip_untrusted_agentops_metadata(result.get("structuredContent"))
    return types.CallToolResult(
        content=content,
        structuredContent=structured,
        isError=bool(result.get("isError")),
        _meta=metadata or None,
    )


async def _list_resources(
    _context: ServerRequestContext[Any],
    params: types.PaginatedRequestParams | None,
    *,
    page_size: int,
    cursor_key: bytes,
) -> types.ListResourcesResult:
    identity = _require_identity("mcp:read")
    result = await _call_gateway("resources_list", identity=identity)
    resources: list[types.Resource] = []
    for item in result.get("resources", []):
        server_id = _required_string(item, "serverId")
        upstream_uri = _required_string(item, "uri")
        resources.append(
            types.Resource(
                name=str(item.get("name") or "Protected resource"),
                title=str(item.get("title")) if item.get("title") is not None else None,
                uri=_resource_reference(identity.project_id, server_id, upstream_uri),
                description=str(item.get("description") or ""),
                mimeType=(str(item.get("mimeType")) if item.get("mimeType") is not None else None),
                _meta={
                    "io.agentops/risk": {
                        "score": item.get("riskScore"),
                        "labels": item.get("riskLabels") or [],
                    },
                    "io.agentops/provenance": item.get("provenance"),
                },
            )
        )
    resources.sort(key=lambda item: str(item.uri))
    page, next_cursor = _paginate(
        resources,
        params,
        kind="resources",
        identity=identity,
        page_size=page_size,
        cursor_key=cursor_key,
    )
    return types.ListResourcesResult(resources=page, next_cursor=next_cursor)


async def _list_resource_templates(
    _context: ServerRequestContext[Any],
    params: types.PaginatedRequestParams | None,
    *,
    page_size: int,
    cursor_key: bytes,
) -> types.ListResourceTemplatesResult:
    identity = _require_identity("mcp:read")
    result = await _call_gateway("resource_templates_list", identity=identity)
    templates: list[types.ResourceTemplate] = []
    for item in result.get("resourceTemplates", []):
        server_id = _required_string(item, "serverId")
        upstream_template = _required_string(item, "uriTemplate")
        annotations = None
        raw_annotations = item.get("annotations")
        if isinstance(raw_annotations, dict):
            try:
                annotations = types.Annotations.model_validate(raw_annotations)
            except ValidationError:
                annotations = None
        templates.append(
            types.ResourceTemplate(
                name=str(item.get("name") or "Protected resource template"),
                title=str(item.get("title")) if item.get("title") is not None else None,
                uriTemplate=_resource_template_reference(
                    identity.project_id,
                    server_id,
                    upstream_template,
                ),
                description=str(item.get("description") or ""),
                mimeType=(str(item.get("mimeType")) if item.get("mimeType") is not None else None),
                annotations=annotations,
                _meta={
                    "io.agentops/risk": {
                        "score": item.get("riskScore"),
                        "labels": item.get("riskLabels") or [],
                    },
                    "io.agentops/provenance": item.get("provenance"),
                },
            )
        )
    templates.sort(key=lambda item: item.uri_template)
    page, next_cursor = _paginate(
        templates,
        params,
        kind="resource_templates",
        identity=identity,
        page_size=page_size,
        cursor_key=cursor_key,
    )
    return types.ListResourceTemplatesResult(
        resourceTemplates=page,
        nextCursor=next_cursor,
    )


async def _read_resource(
    _context: ServerRequestContext[Any],
    params: types.ReadResourceRequestParams,
) -> types.ReadResourceResult:
    identity = _require_identity("mcp:read")
    listed = await _call_gateway("resources_list", identity=identity)
    source = _match_resource_source(
        identity.project_id,
        params.uri,
        listed.get("resources", []),
    )
    upstream_uri = None
    if source is not None:
        upstream_uri = _required_string(source, "uri")
    else:
        listed_templates = await _call_gateway(
            "resource_templates_list",
            identity=identity,
        )
        source, upstream_uri = _find_resource_template_source(
            identity.project_id,
            params.uri,
            listed_templates.get("resourceTemplates", []),
        )
    result = await _call_gateway(
        "resources_read",
        payload={
            "serverId": _required_string(source, "serverId"),
            "uri": upstream_uri,
        },
        identity=identity,
    )
    if result.get("isError"):
        raise MCPError(-32000, "Resource read was rejected")
    contents: list[types.TextResourceContents | types.BlobResourceContents] = []
    try:
        for item in result.get("contents", []):
            if not isinstance(item, dict):
                continue
            safe_item = strip_untrusted_agentops_metadata(item)
            contents.append(
                _RESOURCE_CONTENT_ADAPTER.validate_python({**safe_item, "uri": params.uri})
            )
    except ValidationError as exc:
        raise MCPError(-32000, "Upstream returned unsupported resource content") from exc
    provenance = result.get("provenance")
    return types.ReadResourceResult(
        contents=contents,
        _meta=({"io.agentops/provenance": provenance} if isinstance(provenance, dict) else None),
    )


async def _list_prompts(
    _context: ServerRequestContext[Any],
    params: types.PaginatedRequestParams | None,
    *,
    page_size: int,
    cursor_key: bytes,
) -> types.ListPromptsResult:
    identity = _require_identity("mcp:read")
    result = await _call_gateway("prompts_list", identity=identity)
    prompts: list[types.Prompt] = []
    for item in result.get("prompts", []):
        server_id = _required_string(item, "serverId")
        upstream_name = _required_string(item, "name")
        arguments = item.get("arguments")
        try:
            parsed_arguments = (
                [types.PromptArgument.model_validate(argument) for argument in arguments]
                if isinstance(arguments, list)
                else None
            )
        except ValidationError as exc:
            raise MCPError(-32000, "Upstream returned an unsupported prompt") from exc
        prompts.append(
            types.Prompt(
                name=_stable_name("prompt", identity.project_id, server_id, upstream_name),
                title=str(item.get("title") or f"{server_id}: {upstream_name}"),
                description=str(item.get("description") or ""),
                arguments=parsed_arguments,
                _meta={
                    "io.agentops/risk": {
                        "score": item.get("riskScore"),
                        "labels": item.get("riskLabels") or [],
                    },
                    "io.agentops/provenance": item.get("provenance"),
                },
            )
        )
    prompts.sort(key=lambda item: item.name)
    page, next_cursor = _paginate(
        prompts,
        params,
        kind="prompts",
        identity=identity,
        page_size=page_size,
        cursor_key=cursor_key,
    )
    return types.ListPromptsResult(prompts=page, next_cursor=next_cursor)


async def _get_prompt(
    _context: ServerRequestContext[Any],
    params: types.GetPromptRequestParams,
) -> types.GetPromptResult:
    identity = _require_identity("mcp:read")
    listed = await _call_gateway("prompts_list", identity=identity)
    source = _find_named_source(
        "prompt",
        identity.project_id,
        params.name,
        listed.get("prompts", []),
    )
    result = await _call_gateway(
        "prompts_get",
        payload={
            "serverId": _required_string(source, "serverId"),
            "name": _required_string(source, "name"),
            "arguments": params.arguments or {},
        },
        identity=identity,
    )
    if result.get("isError"):
        raise MCPError(-32000, "Prompt retrieval was rejected")
    try:
        messages = [
            _PROMPT_MESSAGE_ADAPTER.validate_python(strip_untrusted_agentops_metadata(message))
            for message in result.get("messages", [])
            if isinstance(message, dict)
        ]
    except ValidationError as exc:
        raise MCPError(-32000, "Upstream returned an unsupported prompt result") from exc
    provenance = result.get("provenance")
    return types.GetPromptResult(
        description=str(result.get("description")) if result.get("description") else None,
        messages=messages,
        _meta=({"io.agentops/provenance": provenance} if isinstance(provenance, dict) else None),
    )


async def _complete(
    _context: ServerRequestContext[Any],
    params: types.CompleteRequestParams,
) -> types.CompleteResult:
    identity = _require_identity("mcp:read")
    context_arguments = params.context.arguments if params.context is not None else None
    if isinstance(params.ref, types.PromptReference):
        listed = await _call_gateway("prompts_list", identity=identity)
        source = _find_named_source(
            "prompt",
            identity.project_id,
            params.ref.name,
            listed.get("prompts", []),
        )
        ref_type = "prompt"
        ref_value = _required_string(source, "name")
    elif isinstance(params.ref, types.ResourceTemplateReference):
        listed = await _call_gateway("resource_templates_list", identity=identity)
        source = _find_resource_template_definition_source(
            identity.project_id,
            params.ref.uri,
            listed.get("resourceTemplates", []),
        )
        ref_type = "resource"
        ref_value = _required_string(source, "uriTemplate")
    else:
        raise MCPError(-32602, "Unsupported MCP completion reference")
    result = await _call_gateway(
        "completion_complete",
        payload={
            "serverId": _required_string(source, "serverId"),
            "refType": ref_type,
            "refValue": ref_value,
            "argument": {
                "name": params.argument.name,
                "value": params.argument.value,
            },
            "context": context_arguments or {},
        },
        identity=identity,
    )
    try:
        completion = types.Completion.model_validate(result.get("completion"))
    except ValidationError as exc:
        raise MCPError(-32000, "Upstream returned an unsupported completion") from exc
    return types.CompleteResult(completion=completion)


def _require_identity(required_scope: str) -> GatewayIdentity:
    access = get_access_token()
    if access is None:
        raise MCPError(-32001, "Authentication required")
    if not _has_scope(access.scopes, required_scope):
        raise MCPError(-32003, "Insufficient scope")
    claims = access.claims or {}
    project_id = claims.get("project_id")
    auth_kind = claims.get("auth_kind")
    actor_id = claims.get("actor_id")
    if not all(isinstance(value, str) and value for value in (project_id, auth_kind, actor_id)):
        raise MCPError(-32001, "Authenticated identity is incomplete")
    agent_id = claims.get("agent_id")
    role = claims.get("role")
    return GatewayIdentity(
        project_id=project_id,
        auth_kind=auth_kind,
        actor_id=actor_id,
        agent_id=agent_id if isinstance(agent_id, str) and agent_id else None,
        role=role if isinstance(role, str) and role else None,
    )


def _has_scope(scopes: list[str], required_scope: str) -> bool:
    prefix = required_scope.split(":", 1)[0]
    scope_set = set(scopes)
    return "admin:*" in scope_set or required_scope in scope_set or f"{prefix}:*" in scope_set


async def _call_gateway(handler_name: str, **kwargs: Any) -> dict[str, Any]:
    def call() -> dict[str, Any]:
        gateway_app = importlib.import_module("agentops_guard.gateway.app")
        handler = getattr(gateway_app, handler_name)
        db: Session = SessionLocal()
        try:
            return handler(db=db, **kwargs)
        finally:
            db.close()

    try:
        with database_http_boundary():
            return await anyio.to_thread.run_sync(call)
    except HTTPException as exc:
        if isinstance(exc, PostToolDatabaseUnavailable):
            raise MCPError(-32053, "Tool output withheld: post-execution database unavailable",
                           data=exc.detail) from None
        if exc.status_code in {401, 403}:
            raise MCPError(-32003, "Access denied") from None
        if exc.status_code == 404:
            raise MCPError(-32004, "Resource not found") from None
        if exc.status_code == 409:
            raise MCPError(-32009, "Request conflict") from None
        if exc.status_code == 429:
            raise MCPError(-32029, "Capacity exceeded") from None
        if exc.status_code == 503:
            raise MCPError(-32053, "Service temporarily unavailable") from None
        raise MCPError(-32000, "Request rejected") from None


def _stable_name(kind: str, project_id: str, server_id: str, value: str) -> str:
    digest = content_digest([kind, project_id, server_id, value])
    return f"agentops_{kind}_{digest[:32]}"


def _resource_reference(project_id: str, server_id: str, uri: str) -> str:
    digest = content_digest(["resource", project_id, server_id, uri])
    return f"agentops://resource/{digest}"


def _find_named_source(
    kind: str,
    project_id: str,
    requested_name: str,
    candidates: Any,
) -> dict[str, Any]:
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            server_id = candidate.get("serverId")
            source_name = candidate.get("name")
            if (
                isinstance(server_id, str)
                and isinstance(source_name, str)
                and _stable_name(kind, project_id, server_id, source_name) == requested_name
            ):
                return candidate
    raise MCPError(-32004, "MCP item not found")


def _match_resource_source(
    project_id: str,
    requested_uri: str,
    candidates: Any,
) -> dict[str, Any] | None:
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            server_id = candidate.get("serverId")
            source_uri = candidate.get("uri")
            if (
                isinstance(server_id, str)
                and isinstance(source_uri, str)
                and _resource_reference(project_id, server_id, source_uri) == requested_uri
            ):
                return candidate
    return None


def _resource_template_reference(
    project_id: str,
    server_id: str,
    template: str,
) -> str:
    parsed = _parse_resource_template(template)
    variables = parsed.variable_names
    if not variables or len(set(variables)) != len(variables):
        raise MCPError(-32000, "Upstream returned an unsupported resource template")
    digest = content_digest(["resource-template", project_id, server_id, template])
    return f"agentops://resource-template/{digest}{{?{','.join(variables)}}}"


def _find_resource_template_source(
    project_id: str,
    requested_uri: str,
    candidates: Any,
) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(requested_uri, str)
        or len(requested_uri) > _MAX_PROTECTED_RESOURCE_URI_LENGTH
    ):
        raise MCPError(-32602, "Invalid protected resource URI")
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            server_id = candidate.get("serverId")
            upstream_value = candidate.get("uriTemplate")
            if not isinstance(server_id, str) or not isinstance(upstream_value, str):
                continue
            upstream_template = _parse_resource_template(upstream_value)
            protected_value = _resource_template_reference(
                project_id,
                server_id,
                upstream_value,
            )
            protected_template = _parse_resource_template(protected_value)
            matched = protected_template.match(
                requested_uri,
                max_uri_length=_MAX_PROTECTED_RESOURCE_URI_LENGTH,
            )
            if matched is None:
                continue
            if any(not isinstance(value, str) for value in matched.values()):
                raise MCPError(-32602, "Invalid protected resource URI")
            required = set(upstream_template.variable_names) - set(
                upstream_template.query_variable_names
            )
            if not required.issubset(matched):
                raise MCPError(-32602, "Missing resource template parameter")
            if protected_template.expand(matched) != requested_uri:
                raise MCPError(-32602, "Invalid protected resource URI")
            expanded = upstream_template.expand(matched)
            if len(expanded) > 65_536:
                raise MCPError(-32602, "Expanded resource URI is too long")
            return candidate, expanded
    raise MCPError(-32004, "MCP resource not found")


def _find_resource_template_definition_source(
    project_id: str,
    requested_template: str,
    candidates: Any,
) -> dict[str, Any]:
    if (
        not isinstance(requested_template, str)
        or len(requested_template) > _MAX_PROTECTED_RESOURCE_URI_LENGTH
    ):
        raise MCPError(-32602, "Invalid protected resource template")
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            server_id = candidate.get("serverId")
            upstream_value = candidate.get("uriTemplate")
            if (
                isinstance(server_id, str)
                and isinstance(upstream_value, str)
                and _resource_template_reference(
                    project_id,
                    server_id,
                    upstream_value,
                )
                == requested_template
            ):
                return candidate
    raise MCPError(-32004, "MCP resource template not found")


def _parse_resource_template(value: str) -> UriTemplate:
    try:
        return UriTemplate.parse(
            value,
            max_length=_MAX_RESOURCE_TEMPLATE_LENGTH,
            max_variables=_MAX_RESOURCE_TEMPLATE_VARIABLES,
        )
    except (InvalidUriTemplate, TypeError, ValueError) as exc:
        raise MCPError(-32000, "Upstream returned an unsupported resource template") from exc


def _request_metadata(meta: dict[str, Any] | None) -> dict[str, str]:
    if meta is None or AGENTOPS_REQUEST_META not in meta:
        return {}
    raw = meta[AGENTOPS_REQUEST_META]
    if not isinstance(raw, dict):
        raise MCPError(-32602, "AgentOps request metadata must be an object")
    result: dict[str, str] = {}
    for wire_name, payload_name in (
        ("runId", "runId"),
        ("idempotencyKey", "idempotencyKey"),
        ("requestId", "requestId"),
    ):
        value = raw.get(wire_name)
        if value is not None:
            if not isinstance(value, str) or not value:
                raise MCPError(-32602, "AgentOps request metadata is invalid")
            result[payload_name] = value
    return result


def _paginate(
    items: list[Any],
    params: types.PaginatedRequestParams | None,
    *,
    kind: str,
    identity: GatewayIdentity,
    page_size: int,
    cursor_key: bytes,
) -> tuple[list[Any], str | None]:
    if page_size < 1:
        raise RuntimeError("MCP page size must be positive")
    scope = content_digest(
        [
            "agentops-mcp-pagination-v1",
            identity.project_id,
            identity.actor_id,
            identity.agent_id,
            kind,
        ]
    )
    snapshot = content_digest([_pagination_item_key(item, kind=kind) for item in items])
    offset = 0
    if params is not None and params.cursor is not None:
        offset = _decode_cursor(
            params.cursor,
            kind=kind,
            scope=scope,
            snapshot=snapshot,
            item_count=len(items),
            cursor_key=cursor_key,
        )
    end = min(offset + page_size, len(items))
    next_cursor = None
    if end < len(items):
        next_cursor = _encode_cursor(
            kind=kind,
            scope=scope,
            snapshot=snapshot,
            offset=end,
            cursor_key=cursor_key,
        )
    return items[offset:end], next_cursor


def _encode_cursor(
    *,
    kind: str,
    scope: str,
    snapshot: str,
    offset: int,
    cursor_key: bytes,
) -> str:
    payload = json.dumps(
        {
            "kind": kind,
            "offset": offset,
            "scope": scope,
            "snapshot": snapshot,
            "version": 1,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    token = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.digest(cursor_key, payload, "sha256")
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"aog1.{token}.{encoded_signature}"


def _decode_cursor(
    cursor: str,
    *,
    kind: str,
    scope: str,
    snapshot: str,
    item_count: int,
    cursor_key: bytes,
) -> int:
    try:
        if len(cursor.encode("utf-8")) > 512 or not cursor.startswith("aog1."):
            raise ValueError
        parts = cursor.split(".")
        if len(parts) != 3 or parts[0] != "aog1" or not parts[1] or not parts[2]:
            raise ValueError
        token, encoded_signature = parts[1:]
        padding = "=" * (-len(token) % 4)
        raw = base64.b64decode(
            (token + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        signature_padding = "=" * (-len(encoded_signature) % 4)
        signature = base64.b64decode(
            (encoded_signature + signature_padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if len(signature) != 32 or not hmac.compare_digest(
            signature,
            hmac.digest(cursor_key, raw, "sha256"),
        ):
            raise ValueError
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_cursor_object)
        if not isinstance(payload, dict) or set(payload) != {
            "kind",
            "offset",
            "scope",
            "snapshot",
            "version",
        }:
            raise ValueError
        offset = payload["offset"]
        if (
            type(payload["version"]) is not int
            or payload["version"] != 1
            or payload["kind"] != kind
            or payload["scope"] != scope
            or payload["snapshot"] != snapshot
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 1
            or offset >= item_count
            or _encode_cursor(
                kind=kind,
                scope=scope,
                snapshot=snapshot,
                offset=offset,
                cursor_key=cursor_key,
            )
            != cursor
        ):
            raise ValueError
        return offset
    except (UnicodeError, binascii.Error, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise MCPError(-32602, "Invalid pagination cursor") from exc


def _cursor_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate cursor key")
        result[key] = value
    return result


def _pagination_item_key(item: Any, *, kind: str) -> str:
    if kind == "resources":
        key = "uri"
    elif kind == "resource_templates":
        key = "uri_template"
    else:
        key = "name"
    if isinstance(item, dict):
        value = item.get(key)
    else:
        value = getattr(item, key, None)
    if value is None:
        raise RuntimeError("MCP pagination item has no stable identifier")
    return str(value)


def _required_string(value: dict[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise MCPError(-32000, "Upstream returned an incomplete MCP item")
    return result
