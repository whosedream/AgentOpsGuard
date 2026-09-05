import json

from sqlalchemy.orm import Session

from agentops_guard.backend.models import McpServer, McpTool
from agentops_guard.backend.schemas import ScanRequest
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.scanner import (
    scan_content,
    should_quarantine_external_content,
)
from agentops_guard.backend.services.mcp_tool_revisions import record_tool_revision
from agentops_guard.gateway.app import _load_tools_from_server


def refresh_mcp_tools(db: Session, server_id: str) -> dict[str, object]:
    server = db.get(McpServer, server_id)
    if not server:
        raise ValueError(f"MCP server not found: {server_id}")
    refreshed = 0
    try:
        tools = _load_tools_from_server(server, strict=True)
        for tool in tools:
            description = tool.get("description") or ""
            input_schema = tool.get("inputSchema", {})
            annotations = tool.get("annotations", {})
            scan = scan_content(
                ScanRequest(
                    project_id=server.project_id,
                    content=json.dumps(tool, ensure_ascii=False, sort_keys=True),
                    source="mcp_tool_description",
                ),
                db,
            )
            status = "quarantined" if should_quarantine_external_content(scan) else "active"
            quarantined = status == "quarantined"
            tool_id = f"{server.id}:{tool.get('name')}"
            row = db.get(McpTool, tool_id)
            if row is None:
                row = McpTool(
                    id=tool_id,
                    project_id=server.project_id,
                    server_id=server.id,
                    name=tool.get("name", "unknown"),
                )
                db.add(row)
            row.description = "" if quarantined else description
            row.input_schema = {} if quarantined else input_schema
            row.annotations = {} if quarantined else annotations
            row.risk_score = scan.risk_score
            row.risk_labels = scan.risk_labels
            row.status = status
            db.flush()
            record_tool_revision(db, server, row, source=tool)
            refreshed += 1
        if server.status == "error":
            server.status = "active"
        record_audit(
            db,
            project_id=server.project_id,
            action="mcp_server.refresh_completed",
            resource_type="mcp_server",
            resource_id=server.id,
            after={"tools": refreshed},
        )
        db.flush()
        return {"status": "completed", "server_id": server_id, "tools": refreshed}
    except Exception as exc:
        server.status = "error"
        record_audit(
            db,
            project_id=server.project_id,
            action="mcp_server.refresh_failed",
            resource_type="mcp_server",
            resource_id=server.id,
            after={
                "error_code": "mcp_refresh_failed",
                "error_type": type(exc).__name__,
            },
        )
        db.flush()
        raise
