# AgentOps Guard MCP Gateway

The MCP Gateway exposes governed MCP-style endpoints while the backend API stores server registry and cached tool metadata.

## Current Security Boundary

The data-plane `/mcp/*` routes do not authenticate callers. Bind the Gateway to loopback or a
trusted private network, or place an authenticated proxy in front of it. `project_id` and
`agentId` are caller-supplied routing/policy fields, not verified identities. Backend registry API
authentication does not protect the separate Gateway port.

`require_approval` stops the upstream call, creates a pending approval, and returns its ID. An
approval-resume/idempotency protocol is not implemented yet, so approval does not currently grant
a retry permission. Refresh tool metadata before use; calls to an uncached tool are not yet
rejected solely because the cache entry is missing.

## Register a Server

Use the backend registry API:

```powershell
curl -X POST http://localhost:8000/v1/mcp/servers `
  -H "Content-Type: application/json" `
  -H "X-AgentOps-Api-Key: dev-agentops-key" `
  -d '{"id":"local_files","name":"local_files","transport":"stdio","command":"python","args":["examples/fake_mcp.py"],"trust_level":"internal"}'
```

Supported transports:

- `stdio`: starts a configured command and exchanges JSON-RPC messages over stdio.
- `streamable_http`: forwards MCP calls to a configured HTTP upstream URL.

## YAML Configuration

```yaml
servers:
  local_files:
    id: local_files
    project_id: default
    transport: stdio
    command: python
    args: ["examples/fake_mcp.py"]
    trust_level: internal
    allowed_agents: ["coding-agent"]
```

Load and run:

```powershell
uv run agentops-guard load-mcp-config mcp-gateway.yaml
uv run agentops-guard gateway --config mcp-gateway.yaml --port 8001
```

## Refresh Tools

Queue a registry refresh:

```powershell
curl -X POST http://localhost:8000/v1/mcp/servers/local_files/refresh `
  -H "X-AgentOps-Api-Key: dev-agentops-key"
```

Refresh scans tool descriptions, stores cached `McpTool` rows, and assigns tool `status`:

- `active`: tool metadata does not cross the high-risk threshold.
- `quarantined`: scanner risk score is high enough to block policy by default.

If an upstream refresh fails, existing cached tools remain available and the server is marked `error`.

## Quarantine and Restore

```powershell
curl -X PATCH http://localhost:8000/v1/mcp/servers/local_files `
  -H "Content-Type: application/json" `
  -H "X-AgentOps-Api-Key: dev-agentops-key" `
  -d '{"status":"quarantined"}'
```

Allowed server statuses are `active`, `quarantined`, `disabled`, and `error`. Manual `quarantined` or `disabled` states are not overwritten by a successful refresh.

## Policy Guard

Tool calls pass through scanner and policy checks:

1. Gateway resolves an active server within the requested project and reads cached tool metadata.
2. Structured tool arguments are scanned before policy evaluation; raw arguments are not stored in
   the policy-decision context.
3. Any non-allow pre-call action stops the upstream call. `require_approval` also creates a pending
   approval request.
4. Upstream output is scanned before returning to the caller. Explicit post-policy `allow`,
   `redact`, and blocking actions are applied separately.
5. Upstream error responses retain the pre-call decision and create an audit event.

## Troubleshooting

- `404 MCP server not found`: server id is missing from the backend registry.
- `isError=true` with policy reason: policy intentionally blocked the tool call.
- Empty tool list: server is not `active`, upstream returned no tools, or stdio command failed.
- Server `error`: latest refresh failed; inspect job error and retry after fixing upstream config.

## Smoke Checks

```powershell
curl http://localhost:8001/mcp/tools/list
curl -X POST http://localhost:8001/mcp/tools/call -H "Content-Type: application/json" -d '{"serverId":"local_files","name":"local_files.echo","arguments":{"text":"hello"}}'
```
