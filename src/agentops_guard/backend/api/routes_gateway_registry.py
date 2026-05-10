from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import require_scope
from agentops_guard.backend.api.serializers import job_out, mcp_server_out, mcp_tool_out
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import McpServer, McpTool
from agentops_guard.backend.schemas import DeleteResponse, JobOut, McpServerConfig, McpServerOut, McpServerUpdate, McpToolOut
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.jobs import QueueUnavailable, create_job, enqueue_job
from agentops_guard.backend.services.projects import ensure_project


v1_router = APIRouter()


@v1_router.post("/mcp/servers", response_model=McpServerOut, dependencies=[Depends(require_scope("mcp:admin"))])
def create_mcp_server(payload: McpServerConfig, db: Session = Depends(get_db)) -> McpServerOut:
    ensure_project(db, payload.project_id)
    server_id = payload.id or new_id("mcpserver")
    row = db.get(McpServer, server_id)
    if row is None:
        row = McpServer(id=server_id, project_id=payload.project_id, name=payload.name, transport=payload.transport)
        db.add(row)
    row.project_id = payload.project_id
    row.name = payload.name
    row.transport = payload.transport
    row.command = payload.command
    row.args = payload.args
    row.url = payload.url
    row.trust_level = payload.trust_level
    row.allowed_agents = payload.allowed_agents
    row.status = "active"
    record_audit(db, project_id=payload.project_id, action="mcp_server.upsert", resource_type="mcp_server", resource_id=server_id, after=payload.model_dump())
    db.commit()
    db.refresh(row)
    return mcp_server_out(row)


@v1_router.get("/mcp/servers", response_model=list[McpServerOut])
def list_mcp_servers(project_id: str = "default", db: Session = Depends(get_db)) -> list[McpServerOut]:
    rows = db.query(McpServer).filter(McpServer.project_id == project_id).order_by(McpServer.created_at.desc()).all()
    return [mcp_server_out(row) for row in rows]


@v1_router.get("/mcp/servers/{server_id}", response_model=McpServerOut)
def get_mcp_server(server_id: str, db: Session = Depends(get_db)) -> McpServerOut:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    return mcp_server_out(row)


@v1_router.patch("/mcp/servers/{server_id}", response_model=McpServerOut, dependencies=[Depends(require_scope("mcp:admin"))])
def update_mcp_server(server_id: str, payload: McpServerUpdate, db: Session = Depends(get_db)) -> McpServerOut:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    updates = payload.model_dump(exclude_unset=True)
    before = mcp_server_out(row).model_dump(mode="json")
    for key, value in updates.items():
        setattr(row, key, value)
    record_audit(db, project_id=row.project_id, action="mcp_server.update", resource_type="mcp_server", resource_id=server_id, before=before, after=updates)
    db.commit()
    db.refresh(row)
    return mcp_server_out(row)


@v1_router.delete("/mcp/servers/{server_id}", response_model=DeleteResponse, dependencies=[Depends(require_scope("mcp:admin"))])
def delete_mcp_server(server_id: str, db: Session = Depends(get_db)) -> DeleteResponse:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    before = mcp_server_out(row).model_dump(mode="json")
    db.query(McpTool).filter(McpTool.server_id == server_id).delete()
    record_audit(db, project_id=row.project_id, action="mcp_server.delete", resource_type="mcp_server", resource_id=server_id, before=before)
    db.delete(row)
    db.commit()
    return DeleteResponse(status="deleted", id=server_id)


@v1_router.get("/mcp/tools", response_model=list[McpToolOut])
def list_mcp_tools(project_id: str = "default", db: Session = Depends(get_db)) -> list[McpToolOut]:
    rows = db.query(McpTool).filter(McpTool.project_id == project_id).order_by(McpTool.created_at.desc()).all()
    return [mcp_tool_out(row) for row in rows]


@v1_router.post("/mcp/servers/{server_id}/refresh", response_model=JobOut, dependencies=[Depends(require_scope("mcp:admin"))])
def refresh_mcp_server(server_id: str, db: Session = Depends(get_db)) -> JobOut:
    row = db.get(McpServer, server_id)
    if not row:
        raise HTTPException(404, "MCP server not found")
    job = create_job(db, row.project_id, "mcp_refresh", {"server_id": server_id})
    try:
        enqueue_job(db, job)
    except QueueUnavailable as exc:
        db.rollback()
        raise HTTPException(503, f"Redis queue unavailable: {exc}") from exc
    record_audit(db, project_id=row.project_id, action="mcp_server.refresh_queued", resource_type="mcp_server", resource_id=server_id, after={"job_id": job.id})
    db.commit()
    db.refresh(job)
    return job_out(job)
