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

Mutating tool calls should include the `runId` returned by `POST /v1/runs`. The Gateway reads the
server-stored original request for that run; a caller-supplied `userIntent` field is ignored.

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
- `streamable_http`: connects to a standard MCP Streamable HTTP endpoint. The URL must be the MCP
  endpoint itself, for example `https://server.example/mcp`. The Gateway performs MCP initialization
  before listing tools/resources/prompts or invoking them.
- `legacy_http`: compatibility mode for the former AgentOps-specific `GET /tools/list` and
  `POST /tools/call` contract. It does not support resources or prompts and should not be used for
  new servers.

Example standard MCP server:

```yaml
servers:
  remote_mcp:
    project_id: default
    transport: streamable_http
    url: https://server.example/mcp
    trust_level: external
```

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

## Optional ToolHive Isolation

ToolHive is an optional runtime around an upstream MCP server; it is not a replacement for this
Gateway's policy, approval, credential, or audit controls. ToolHive runs the server in a container
and exposes a standard Streamable HTTP proxy, so AgentOps Guard uses the same
`streamable_http` transport.

Start with ToolHive's built-in no-permission profile and a loopback-only proxy. The example server
below needs no filesystem or network access:

```bash
thv run npx://@modelcontextprotocol/server-everything \
  --name agentops-sandbox-smoke \
  --permission-profile none \
  --proxy-mode streamable-http \
  --proxy-port 4484 \
  --host 127.0.0.1 \
  --strict-protocol-validation \
  --enable-audit
```

Use the exact MCP endpoint printed by `thv status agentops-sandbox-smoke`; do not assume a path for
other ToolHive transports or versions. Put that endpoint into
`deploy/toolhive/agentops-toolhive.example.yaml`, then load it with the normal
`load-mcp-config` command. A ToolHive-backed registry entry must use
`runtime_provider: toolhive`, `transport: streamable_http`, and `trust_level: sandboxed`; the API
rejects weaker combinations.

For servers that need outbound access, replace `none` with a reviewed custom permission profile
that lists exact hosts and ports. Do not use the broad `network` profile by default, mount the
Docker socket into AgentOps Guard, pass raw secrets with `--env`, or use ToolHive's direct
`--remote-auth-bearer-token` flag. Secret-bearing servers should use ToolHive secret references or
the AgentOps `credential_ref` trusted execution path.

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
3. Send, write, delete, payment, and permission actions are compared with the server-derived run
   intent. Missing intent, a missing action, or a changed target requires approval before upstream
   execution. Tool annotations can raise risk but cannot lower it. An external tool with no known
   action also requires approval until an administrator reviews the server and marks it internal.
4. Any non-allow pre-call action stops the upstream call. `require_approval` also creates a pending
   approval request.
5. Upstream tool output, resources, prompts, and their descriptions are scanned before returning to
   the caller. Explicit post-policy `allow`,
   `redact`, and blocking actions are applied separately.
6. Upstream error responses retain the pre-call decision and create an audit event.

## Troubleshooting

- `404 MCP server not found`: server id is missing from the backend registry.
- `isError=true` with policy reason: policy intentionally blocked the tool call.
- Empty tool list: server is not `active`, upstream returned no tools, or stdio command failed.
- Server `error`: latest refresh failed; inspect job error and retry after fixing upstream config.

## Smoke Checks

```powershell
curl http://localhost:8001/mcp/tools/list
curl -X POST http://localhost:8001/mcp/tools/call -H "Content-Type: application/json" -d '{"serverId":"local_files","name":"local_files.echo","arguments":{"text":"hello"},"agentId":"coding-agent","runId":"run_from_backend"}'
```
