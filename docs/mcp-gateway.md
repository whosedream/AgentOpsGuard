# AgentOps Guard MCP Gateway

The MCP Gateway exposes governed MCP-style endpoints while the backend API stores server registry and cached tool metadata.

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

1. Gateway reads server and cached tool metadata.
2. Pre-call policy blocks quarantined tools or disallowed agents.
3. Upstream output is scanned before returning to the caller.
4. High-risk output can be redacted, denied, or quarantined according to policy.

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
