from __future__ import annotations

import json
import time
from collections import Counter
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


REQUEST_COUNTS: Counter[tuple[str, str, int]] = Counter()
REQUEST_LATENCY_MS: Counter[tuple[str, str]] = Counter()


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or f"req_{uuid4().hex}"
        start = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = int((time.perf_counter() - start) * 1000)
        route = request.url.path
        REQUEST_COUNTS[(request.method, route, response.status_code)] += 1
        REQUEST_LATENCY_MS[(request.method, route)] += duration_ms
        response.headers["X-Request-Id"] = request_id
        log_record = {
            "request_id": request_id,
            "method": request.method,
            "path": route,
            "status": response.status_code,
            "duration_ms": duration_ms,
        }
        project_id = request.query_params.get("project_id")
        if project_id:
            log_record["project_id"] = project_id
        print(json.dumps(log_record, separators=(",", ":")), flush=True)
        return response


def request_metrics_lines() -> list[str]:
    lines = [
        "# HELP agentops_api_requests_total Total API requests",
        "# TYPE agentops_api_requests_total counter",
    ]
    for (method, route, status), count in REQUEST_COUNTS.items():
        lines.append(f'agentops_api_requests_total{{method="{method}",route="{route}",status="{status}"}} {count}')
    lines += [
        "# HELP agentops_api_request_latency_ms_total Total API request latency in milliseconds",
        "# TYPE agentops_api_request_latency_ms_total counter",
    ]
    for (method, route), total in REQUEST_LATENCY_MS.items():
        lines.append(f'agentops_api_request_latency_ms_total{{method="{method}",route="{route}"}} {total}')
    return lines
