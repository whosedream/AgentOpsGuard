from __future__ import annotations

from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from agentops_guard.backend.config import get_settings


_provider: TracerProvider | None = None


def _service_resource(service_name: str) -> Resource:
    return Resource({"service.name": service_name})


def configure_telemetry(default_service_name: str) -> None:
    global _provider
    settings = get_settings()
    if not settings.otel_enabled or _provider is not None:
        return
    service_name = settings.otel_service_name or default_service_name
    provider = TracerProvider(
        resource=_service_resource(service_name),
        sampler=ParentBased(TraceIdRatioBased(settings.otel_trace_sample_ratio)),
    )
    exporter = OTLPSpanExporter(
        endpoint=settings.otel_exporter_otlp_endpoint,
        insecure=settings.otel_exporter_otlp_endpoint.startswith("http://"),
        timeout=settings.otel_export_timeout_seconds,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _provider = provider


class TelemetryMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, component: str) -> None:
        super().__init__(app)
        self._component = component
        self._tracer = trace.get_tracer(f"agentops_guard.{component}")

    async def dispatch(self, request: Request, call_next):
        parent_context = propagate.extract(request.headers)
        with self._tracer.start_as_current_span(
            f"HTTP {request.method}",
            context=parent_context,
            kind=SpanKind.SERVER,
            attributes={
                "http.request.method": request.method,
                "agentops.component": self._component,
            },
        ) as span:
            try:
                response = await call_next(request)
            except Exception:
                span.set_status(Status(StatusCode.ERROR))
                raise
            route = request.scope.get("route")
            route_path = getattr(route, "path", None)
            if isinstance(route_path, str) and route_path:
                span.update_name(f"{request.method} {route_path}")
                span.set_attribute("http.route", route_path)
            else:
                span.update_name(f"{request.method} <unmatched>")
            span.set_attribute("http.response.status_code", response.status_code)
            if response.status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))
            return response


def inject_trace_headers(headers: dict[str, str]) -> None:
    propagate.inject(headers)
