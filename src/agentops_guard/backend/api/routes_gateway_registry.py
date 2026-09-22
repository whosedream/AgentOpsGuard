from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from agentops_guard.backend.auth import (
    AuthContext,
    authorize_project_access,
    get_auth_context,
    require_scope,
)
from agentops_guard.backend.api.serializers import job_out, mcp_server_out, mcp_tool_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import McpServer, McpTool
from agentops_guard.backend.schemas import (
    DeleteResponse,
    JobOut,
    McpServerConfig,
    McpServerOut,
    McpServerUpdate,
    McpToolOut,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.jobs import create_job
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.tool_receipts import ReceiptContract, validate_contract


v1_router = APIRouter()


class ToolExecutionPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    revision_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    queue_enabled: bool = False
    retry_mode: Literal["never", "read_only"] = "never"
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_contract: ReceiptContract | None = None


@v1_router.put("/mcp/tools/{tool_id}/execution-policy",
               dependencies=[Depends(require_scope("mcp:admin"))])
def configure_tool_execution_policy(
    tool_id: str, payload: ToolExecutionPolicyUpdate, request: Request,
    db: Session = Depends(get_db),
) -> dict:
    from datetime import UTC, datetime
    from agentops_guard.backend.models import ToolExecutionPolicy
    from agentops_guard.backend.services.tool_invocations import current_revision

    auth = get_auth_context(request)
    authorize_project_access(auth, payload.project_id, db=db)
    revision = current_revision(db, payload.project_id, tool_id)
    if revision.content_digest != payload.revision_digest:
        raise HTTPException(409, "Review must match the current tool revision")
    if payload.receipt_contract is not None:
        if payload.retry_mode != "never":
            raise HTTPException(400, "Receipt-enabled tools must query, never automatically replay")
        validate_contract(db, payload.project_id, tool_id, payload.receipt_contract)
    row = db.get(ToolExecutionPolicy, tool_id)
    if row is None:
        row = ToolExecutionPolicy(tool_id=tool_id, project_id=payload.project_id)
        db.add(row)
    row.revision_digest = payload.revision_digest
    row.queue_enabled = payload.queue_enabled
    row.retry_mode = payload.retry_mode
    row.evidence_sha256 = payload.evidence_sha256
    row.receipt_contract = (
        payload.receipt_contract.model_dump() if payload.receipt_contract else None
    )
    row.updated_by = auth.actor_id or auth.kind
    row.updated_at = datetime.now(UTC)
    record_audit(db, project_id=payload.project_id, action="mcp_tool.execution_policy_reviewed",
                 resource_type="mcp_tool", resource_id=tool_id, after=payload.model_dump())
    db.commit()
    return {"tool_id": tool_id, **payload.model_dump()}


@v1_router.post(
    "/mcp/servers", response_model=McpServerOut, dependencies=[Depends(require_scope("mcp:admin"))]
)
def create_mcp_server(
    payload: McpServerConfig, request: Request, db: Session = Depends(get_db)
) -> McpServerOut:
    authorize_project_access(get_auth_context(request), payload.project_id, db=db)
    ensure_project(db, payload.project_id)
    server_id = payload.id or new_id("mcpserver")
    row = db.get(McpServer, server_id)
    if row is None:
        row = McpServer(
            id=server_id,
            project_id=payload.project_id,
            name=payload.name,
            transport=payload.transport,
        )
        db.add(row)
    row.project_id = payload.project_id
    row.name = payload.name
    row.transport = payload.transport
    row.runtime_provider = payload.runtime_provider
    row.command = payload.command
    row.args = payload.args
    row.url = payload.url
    row.trust_level = payload.trust_level
    row.allowed_agents = payload.allowed_agents
    row.status = "active"
    record_audit(
        db,
        project_id=payload.project_id,
        action="mcp_server.upsert",
        resource_type="mcp_server",
        resource_id=server_id,
        after=payload.model_dump(),
    )
    db.commit()
    db.refresh(row)
    return mcp_server_out(row)


@v1_router.get("/mcp/servers", response_model=list[McpServerOut])
def list_mcp_servers(
    project_id: str = "default",
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[McpServerOut]:
    authorize_project_access(auth, project_id, db=db)
    rows = (
        db.query(McpServer)
        .filter(McpServer.project_id == project_id)
        .order_by(McpServer.created_at.desc())
        .all()
    )
    return [mcp_server_out(row) for row in rows]


@v1_router.get("/mcp/servers/{server_id}", response_model=McpServerOut)
def get_mcp_server(server_id: str, request: Request, db: Session = Depends(get_db)) -> McpServerOut:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    return mcp_server_out(row)


@v1_router.patch(
    "/mcp/servers/{server_id}",
    response_model=McpServerOut,
    dependencies=[Depends(require_scope("mcp:admin"))],
)
def update_mcp_server(
    server_id: str, payload: McpServerUpdate, request: Request, db: Session = Depends(get_db)
) -> McpServerOut:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    updates = payload.model_dump(exclude_unset=True)
    candidate_runtime = updates.get("runtime_provider", row.runtime_provider)
    candidate_transport = updates.get("transport", row.transport)
    candidate_url = updates.get("url", row.url)
    candidate_trust = updates.get("trust_level", row.trust_level)
    if candidate_runtime == "toolhive" and (
        candidate_transport != "streamable_http"
        or not candidate_url
        or candidate_trust != "sandboxed"
    ):
        raise HTTPException(
            422,
            "ToolHive servers require streamable_http, a URL, and sandboxed trust",
        )
    before = mcp_server_out(row).model_dump(mode="json")
    for key, value in updates.items():
        setattr(row, key, value)
    record_audit(
        db,
        project_id=row.project_id,
        action="mcp_server.update",
        resource_type="mcp_server",
        resource_id=server_id,
        before=before,
        after=updates,
    )
    db.commit()
    db.refresh(row)
    return mcp_server_out(row)


@v1_router.delete(
    "/mcp/servers/{server_id}",
    response_model=DeleteResponse,
    dependencies=[Depends(require_scope("mcp:admin"))],
)
def delete_mcp_server(
    server_id: str, request: Request, db: Session = Depends(get_db)
) -> DeleteResponse:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    before = mcp_server_out(row).model_dump(mode="json")
    db.query(McpTool).filter(McpTool.server_id == server_id).delete()
    record_audit(
        db,
        project_id=row.project_id,
        action="mcp_server.delete",
        resource_type="mcp_server",
        resource_id=server_id,
        before=before,
    )
    db.delete(row)
    db.commit()
    return DeleteResponse(status="deleted", id=server_id)


@v1_router.get("/mcp/tools", response_model=list[McpToolOut])
def list_mcp_tools(
    project_id: str = "default",
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[McpToolOut]:
    authorize_project_access(auth, project_id, db=db)
    rows = (
        db.query(McpTool)
        .filter(McpTool.project_id == project_id)
        .order_by(McpTool.created_at.desc())
        .all()
    )
    return [mcp_tool_out(row) for row in rows]


@v1_router.post(
    "/mcp/servers/{server_id}/refresh",
    response_model=JobOut,
    dependencies=[Depends(require_scope("mcp:admin"))],
)
def refresh_mcp_server(server_id: str, request: Request, db: Session = Depends(get_db)) -> JobOut:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    authorize_project_access(get_auth_context(request), row.project_id, conceal=True, db=db)
    job = create_job(db, row.project_id, "mcp_refresh", {"server_id": server_id})
    record_audit(
        db,
        project_id=row.project_id,
        action="mcp_server.refresh_queued",
        resource_type="mcp_server",
        resource_id=server_id,
        after={"job_id": job.id},
    )
    db.commit()
    db.refresh(job)
    return job_out(job)
