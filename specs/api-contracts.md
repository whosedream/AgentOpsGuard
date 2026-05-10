# AgentOps Guard GUI API Contracts

All protected backend requests require `X-AgentOps-Api-Key: dev-agentops-key` in local development.
The Dashboard BFF proxies `/api/backend/*` and `/api/gateway/*` must preserve query strings for filtered, paginated, and project-scoped requests.

## System

### GET /healthz

Returns `{ "status": "ok" }` when the API process is alive.

### GET /readyz

Checks database and Redis. Returns `200` when both are available, otherwise `503` with component details.

### GET /metrics

Returns Prometheus text metrics with `text/plain` content type.
Includes API request counters and latency totals keyed by method, route, and status.

All API responses include `X-Request-Id`. If the request supplies this header, the same value is returned; otherwise the API generates one.

### GET /v1/system/status

Response:

```json
{
  "api": {"status": "ok"},
  "database": {"status": "ok"},
  "gateway": {"url": "http://localhost:8001", "status": "unknown"},
  "counts": {"runs": 0, "risks": 0, "eval_suites": 0, "eval_runs": 0, "replays": 0, "mcp_servers": 0, "mcp_tools": 0},
  "config": {"project_id": "default", "store_raw_content": false, "policy_fail_mode": "closed_for_high_risk"}
}
```

## Replay

### GET /v1/replays?project_id=default&source_run_id=&limit=50

Returns `ReplayOut[]`, newest first. `source_run_id` is optional.
Pass `page_mode=envelope&cursor=0` to receive `{ "items": ReplayOut[], "next_cursor": "..." }`.

### POST /v1/replays

Existing contract. Creates replay from `ReplayCreate`.

### POST /v1/replays/jobs

Queues a Redis/RQ replay job and returns `JobOut`. Returns `503` if Redis is unavailable.

## Eval

### GET /v1/eval-runs?project_id=default&suite_id=&limit=50

Returns `EvalRunOut[]`, newest first. `suite_id` is optional.
Pass `page_mode=envelope&cursor=0` to receive `{ "items": EvalRunOut[], "next_cursor": "..." }`.

### POST /v1/eval-suites/{suite_id}/run

Runs the suite and returns `EvalRunOut`. 404 if suite is missing.

### POST /v1/eval-runs/jobs

Queues a Redis/RQ eval job and returns `JobOut`. Returns `503` if Redis is unavailable.

### POST /v1/eval-suites/{suite_id}/jobs

Queues a Redis/RQ eval suite run job and returns `JobOut`. Returns `404` if suite is missing.

## Jobs

### GET /v1/jobs?project_id=default&kind=&limit=50

Returns `JobOut[]`, newest first. Supports `page_mode=envelope`.

### GET /v1/jobs/{id}

Returns `JobOut` or 404.

## API Keys and Audit

### POST /v1/api-keys

Creates a hashed API key and returns the plaintext token once in `token`.

### GET /v1/api-keys

Lists API keys without plaintext token values.

### DELETE /v1/api-keys/{id}

Revokes the API key and writes an audit log entry.

### GET /v1/audit-logs

Lists audit logs. Supports `page_mode=envelope`.

## MCP Registry

### GET /v1/mcp/servers/{id}

Returns `McpServerOut` or 404.

### GET /v1/mcp/servers

Returns `McpServerOut[]`, newest first for the requested `project_id`. Each item includes `status`, which can be `active`, `quarantined`, `disabled`, or `error`.

### PATCH /v1/mcp/servers/{id}

Request accepts partial server fields: `name`, `transport`, `command`, `args`, `url`, `trust_level`, `allowed_agents`, `status`.
`status` accepts only `active`, `quarantined`, `disabled`, and `error`; invalid values return `422`.
Returns `McpServerOut`.

### DELETE /v1/mcp/servers/{id}

Deletes server and associated cached tools. Returns `{ "status": "deleted", "id": "..." }`. 404 if missing.

### POST /v1/mcp/servers/{id}/refresh

Queues a Redis/RQ MCP refresh job and returns `JobOut`. Existing cached tools remain on refresh failure.
The refresh worker loads upstream tools through the configured Gateway transport, updates cached tools on success, marks the server `error` on upstream failure, and writes audit logs for success or failure.
Manual `quarantined` and `disabled` server states are preserved by refresh; only a previously `error` server is restored to `active` after a successful refresh.

### GET /v1/mcp/tools

Returns cached `McpToolOut[]`, newest first for the requested `project_id`. Each item includes `status`, `risk_score`, and `risk_labels` so the Dashboard can show active/quarantined risk state without reloading upstream tools.

## Scanner, Policy, Gateway

Existing scanner and policy request/response contracts are unchanged. Gateway endpoints must allow browser CORS and return JSON for tools list, tool call, resource read, and prompt get.


## Operations Hardening

### GET /readyz

Response remains backward compatible and includes `status`, `database`, and `redis`. v0.7 adds `migration`:

```json
{
  "status": {"status": "ok"},
  "database": {"status": "ok"},
  "redis": {"status": "ok", "url": "redis://localhost:6379/0"},
  "migration": {"status": "ok", "detail": "head=0002_control_plane"}
}
```

- `database.status=error`, `redis.status=error`, or `migration.status=error` returns HTTP `503`.
- Local SQLite development databases without `alembic_version` return `migration.status=skipped` and stay ready.
- Postgres or migrated SQLite databases must have `alembic_version` equal to Alembic head.

### GET /metrics

Prometheus text metrics include the existing request, run, risk, and job gauges plus v0.7 operational gauges:

- `agentops_policy_decisions_total{action,severity}`
- `agentops_approvals_pending`
- `agentops_policy_packs_total{status}`
- `agentops_scan_rules_total{status,severity}`
- `agentops_mcp_servers_total{status}`
- `agentops_mcp_tools_total{status}`
- `agentops_jobs_by_status_total{kind,status}`

Metric labels are intentionally low-cardinality; request IDs, run IDs, and resource IDs must not appear in metric labels.

### Request Logs

API request logs are JSON lines written to stdout. Required fields are `request_id`, `method`, `path`, `status`, and `duration_ms`; `project_id` is included when present in the query string.

## v0.7 Governance APIs

The governance control plane is additive and keeps existing v1 routes compatible:

- `GET /v1/control-plane/status?project_id=default` returns project config plus approval, policy-pack, scan-rule, suppression, and run-status counts.
- `POST /v1/projects` and `PATCH /v1/projects/{project_id}` manage project retention, raw-content storage, policy fail mode, status, and metadata.
- `GET /v1/approvals` and `POST /v1/approvals/{approval_id}/review` expose approval queues and review actions.
- `POST /v1/policy-packs` and `PATCH /v1/policy-packs/{pack_id}` manage deterministic project policy packs.
- `POST /v1/scanner/rules` and `PATCH /v1/scanner/rules/{rule_id}` manage project-specific scanner regex rules.
- `POST /v1/runs/{run_id}/suppressions` and `PATCH /v1/suppressions/{suppression_id}` manage known-benign run suppressions.
