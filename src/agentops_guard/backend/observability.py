from __future__ import annotations

import json
import time
from uuid import uuid4

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

PROMETHEUS_REGISTRY = CollectorRegistry()
REQUEST_COUNTER = Counter(
    "agentops_api_requests_total",
    "Total API requests",
    ("method", "route", "status"),
    registry=PROMETHEUS_REGISTRY,
)
REQUEST_LATENCY = Histogram(
    "agentops_api_request_latency_ms",
    "API request latency in milliseconds",
    ("method", "route"),
    registry=PROMETHEUS_REGISTRY,
    buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000),
)
RUNS_GAUGE = Gauge("agentops_runs_total", "Total runs", registry=PROMETHEUS_REGISTRY)
RISKS_GAUGE = Gauge("agentops_risks_total", "Total risk events", registry=PROMETHEUS_REGISTRY)
JOBS_GAUGE = Gauge("agentops_jobs_total", "Total background jobs", registry=PROMETHEUS_REGISTRY)
POLICY_DECISIONS_GAUGE = Gauge(
    "agentops_policy_decisions_total",
    "Total policy decisions by action and severity",
    ("action", "severity"),
    registry=PROMETHEUS_REGISTRY,
)
APPROVALS_PENDING_GAUGE = Gauge(
    "agentops_approvals_pending", "Total pending approvals", registry=PROMETHEUS_REGISTRY
)
POLICY_PACKS_GAUGE = Gauge(
    "agentops_policy_packs_total",
    "Total policy packs by status",
    ("status",),
    registry=PROMETHEUS_REGISTRY,
)
SCAN_RULES_GAUGE = Gauge(
    "agentops_scan_rules_total",
    "Total scan rules by status and severity",
    ("status", "severity"),
    registry=PROMETHEUS_REGISTRY,
)
MCP_SERVERS_GAUGE = Gauge(
    "agentops_mcp_servers_total",
    "Total MCP servers by status",
    ("status",),
    registry=PROMETHEUS_REGISTRY,
)
MCP_TOOLS_GAUGE = Gauge(
    "agentops_mcp_tools_total",
    "Total MCP tools by status",
    ("status",),
    registry=PROMETHEUS_REGISTRY,
)
JOBS_BY_STATUS_GAUGE = Gauge(
    "agentops_jobs_by_status_total",
    "Total background jobs by kind and status",
    ("kind", "status"),
    registry=PROMETHEUS_REGISTRY,
)
OUTBOX_BY_STATUS_GAUGE = Gauge(
    "agentops_outbox_events_total",
    "Total transactional outbox events by status",
    ("status",),
    registry=PROMETHEUS_REGISTRY,
)
EXECUTIONS_BY_STATUS_GAUGE = Gauge(
    "agentops_execution_requests_total",
    "Total durable execution requests by status",
    ("status",),
    registry=PROMETHEUS_REGISTRY,
)
JOB_LEASE_RECOVERIES_COUNTER = Counter(
    "agentops_job_lease_recoveries_total",
    "Background jobs recovered after an expired worker lease",
    ("outcome",),
    registry=PROMETHEUS_REGISTRY,
)
JOB_HEARTBEAT_FAILURES_COUNTER = Counter(
    "agentops_job_heartbeat_failures_total",
    "Background job heartbeat failures",
    ("reason",),
    registry=PROMETHEUS_REGISTRY,
)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or f"req_{uuid4().hex}"
        request.state.request_id = request_id
        start = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = int((time.perf_counter() - start) * 1000)
        matched_route = request.scope.get("route")
        route = getattr(matched_route, "path", "unmatched")
        REQUEST_COUNTER.labels(
            method=request.method, route=route, status=str(response.status_code)
        ).inc()
        REQUEST_LATENCY.labels(method=request.method, route=route).observe(duration_ms)
        response.headers["X-Request-Id"] = request_id
        log_record = {
            "request_id": request_id,
            "method": request.method,
            "path": route,
            "status": response.status_code,
            "duration_ms": duration_ms,
        }
        print(json.dumps(log_record, separators=(",", ":")), flush=True)
        return response


def metrics_payload() -> bytes:
    return generate_latest(PROMETHEUS_REGISTRY)
