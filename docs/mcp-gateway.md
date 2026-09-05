# AgentOps Guard MCP Gateway

The MCP Gateway exposes a standard MCP Streamable HTTP endpoint while the backend API stores server
registry and cached tool metadata. The earlier AgentOps HTTP routes remain as a compatibility layer.

## Current Security Boundary

Every Gateway route is authenticated. The standard `/mcp` endpoint accepts only Bearer credentials;
the compatibility routes also accept the project API-key header. The verified credential supplies
the project, Agent and permission range. Query parameters, request bodies and MCP metadata cannot
change that identity. Reading requires `mcp:read`; tool invocation requires `mcp:invoke`.

The standard endpoint is implemented with the official MCP Python SDK and calls the existing
Gateway handlers. It therefore does not create a second route around scanning, action/target
alignment, policy, approval or audit. Tool names and resource addresses exposed to clients are
project-bound opaque identifiers; upstream resource addresses are not returned to the Agent.

`require_approval` stops the upstream call and creates both a pending approval and a durable
execution request without storing raw tool arguments. After approval, the same authenticated Agent
must repeat the exact call; changed identity, run, arguments, tool version or policy version cannot
reuse it. An upstream result marked unknown is not retried automatically.

Stdio reads enforce the configured wall-clock timeout even if the child process produces no output.
The timed-out child is replaced, and all managed stdio processes close during Gateway shutdown. If
the tool completed its external action before its response was lost, the claimed execution is
stored as `outcome_unknown`; repeating the same approved request is rejected until an operator
checks the external system. The operator records only the SHA-256 of evidence kept outside
AgentOps Guard. Confirmed success or failure closes the request. Only confirmed non-execution moves
the same request back to `approved`; its original expiry, identity, tool revision, argument digest,
and policy snapshot are checked again before one new claimant can execute it.
If the Gateway loses the execution claim while an upstream call is in flight, it discards the
upstream result, returns the fixed `execution_claim_lost` error, and writes an audit event containing
only internal identifiers and status metadata.

Mutating tool calls should include the `runId` returned by `POST /v1/runs`. The Gateway reads the
server-stored original request for that run; a caller-supplied `userIntent` field is ignored.

For standard MCP calls, put `runId` and the optional `idempotencyKey` under request metadata key
`io.agentops/request`. No other request metadata changes authorization. Tool, fixed-resource,
resource-template and prompt lists use standard opaque MCP cursors. A cursor is bound to the authenticated project, actor, Agent,
list type and stable visible-item snapshot, then authenticated by the trusted Gateway process;
malformed, modified, cross-identity, cross-list and stale cursors return MCP `-32602` without
exposing upstream identifiers. `AGENTOPS_MCP_PAGE_SIZE` sets the
server-selected page size from 1 to 1,000 and defaults to 100. The exact token and verification
contract is recorded in `specs/mcp-pagination-v1.md`.

Every tool description/result, fixed or templated resource, and prompt returned by the Gateway carries a server-built
content provenance marker. Standard MCP exposes it under `_meta["io.agentops/provenance"]`; the
compatibility routes use a top-level `provenance` field. The marker records only source class,
server-derived trust, an opaque source reference, transformations, and an optional redacted content
reference. Before scanning, the Gateway recursively removes any upstream `io.agentops/*` fields, so
an MCP server cannot label its own output as trusted or forge a control decision. Quarantined content
does not expose its content reference.

Clients that transform, summarize, or concatenate MCP content must preserve the marker and use the
most restrictive parent trust. Missing and unknown provenance means untrusted. This metadata helps
the Agent Harness keep external data separate from instructions, but cannot replace deterministic
action authorization. See `specs/content-provenance-v1.md`.

## Standard MCP Client Endpoint

Point an MCP Streamable HTTP client at `http://localhost:8001/mcp` for local development. Production
must set `AGENTOPS_MCP_PUBLIC_URL` to the public HTTPS `/mcp` address and configure exact
`AGENTOPS_MCP_ALLOWED_HOSTS` and `AGENTOPS_MCP_ALLOWED_ORIGINS` values. The Helm Ingress sends
`/mcp` to the Gateway while the remaining paths continue to the Dashboard.

The endpoint supports paginated listing and calling tools, paginated listing of fixed resources and
resource templates, reading an expanded protected template, paginated listing and getting prompts,
and MCP `completion/complete` for currently advertised prompt and resource-template arguments.
Template parsing, matching, and expansion reuse the official SDK's bounded RFC 6570 implementation;
the exact protected-reference contract is in `specs/mcp-resource-templates-v1.md`. Completion uses
those same protected references, rejects undeclared or credential-bearing inputs before upstream,
and scans and bounds every returned suggestion before it reaches a client; see
`specs/mcp-completion-v1.md`. Pagination remains
stateless. The older `/mcp/tools/*`,
`/mcp/resources/*`, `/mcp/prompts/*`, and `/mcp/completion/complete` routes remain for existing
integrations and use the same security handlers.

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

The version-controlled equivalent is
`deploy/toolhive/permission-profiles/no-access.json`. For production, start a server from a reviewed
ToolHive registry entry through the guarded launcher instead of typing a direct image reference:

```bash
uv run python scripts/run_toolhive_verified.py reviewed-server \
  --name reviewed-server-prod \
  --proxy-port 4484
```

This launcher turns on ToolHive provenance verification, isolates the network, binds the proxy to
loopback, enables protocol validation and audit, and rejects profiles that enable privileged mode,
unrestricted egress, host networking, or wildcard destinations. A private ToolHive registry entry
must include the expected signer and source provenance. A direct image without provenance is
rejected by strict mode even when it is pinned by digest.

After starting a no-access workload, compare the stored permission declaration with Docker's actual
state:

```bash
uv run python scripts/verify_toolhive_no_access_runtime.py reviewed-server-prod
```

The check requires a digest-pinned image, Docker network mode `none`, no host mounts or devices,
non-privileged execution, all Linux capabilities dropped, and no host PID/IPC namespace. It does
not prove container-runtime escape resistance.

Use the exact MCP endpoint printed by `thv status agentops-sandbox-smoke`; do not assume a path for
other ToolHive transports or versions. Put that endpoint into
`deploy/toolhive/agentops-toolhive.example.yaml`, then load it with the normal
`load-mcp-config` command. A ToolHive-backed registry entry must use
`runtime_provider: toolhive`, `transport: streamable_http`, and `trust_level: sandboxed`; the API
rejects weaker combinations.

For servers that need outbound access, replace `none` with a reviewed custom permission profile
that uses bridge mode and lists exact hosts and ports. The guarded launcher rejects wildcard hosts
and unrestricted outbound access. Do not use the broad `network` profile by default, mount the
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
6. Upstream AgentOps metadata is removed and replaced with a Gateway-generated untrusted provenance
   marker. The marker is also stored with the redacted content reference.
7. Upstream error responses retain the pre-call decision and create an audit event.

## Troubleshooting

- `404 MCP server not found`: server id is missing from the backend registry.
- `isError=true` with policy reason: policy intentionally blocked the tool call.
- Empty tool list: server is not `active`, upstream returned no tools, or stdio command failed.
- Server `error`: latest refresh failed; inspect job error and retry after fixing upstream config.

## Smoke Checks

```powershell
$headers = @{ Authorization = "Bearer " + $env:AGENTOPS_MCP_TOKEN }
Invoke-RestMethod http://localhost:8001/mcp/tools/list -Headers $headers
Invoke-RestMethod -Method Post http://localhost:8001/mcp/tools/call -Headers $headers -ContentType "application/json" -Body '{"serverId":"local_files","name":"local_files.echo","arguments":{"text":"hello"},"runId":"run_from_backend"}'
```
