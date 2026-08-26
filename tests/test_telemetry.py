from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agentops_guard.backend.telemetry import TelemetryMiddleware


def test_http_spans_exclude_headers_query_and_body(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("telemetry-test")
    monkeypatch.setattr(trace, "get_tracer", lambda *_args, **_kwargs: tracer)
    app = FastAPI()
    app.add_middleware(TelemetryMiddleware, component="api")

    @app.post("/scan")
    def scan() -> dict[str, str]:
        return {"status": "ok"}

    secret = "secret-canary-never-enter-telemetry"
    with TestClient(app) as client:
        response = client.post(
            "/scan",
            params={"payload": secret},
            headers={"Authorization": f"Bearer {secret}"},
            json={"content": secret},
        )

    assert response.status_code == 200
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    serialized = json.dumps(dict(spans[0].attributes))
    assert secret not in serialized
    assert spans[0].attributes["http.route"] == "/scan"
    assert spans[0].attributes["agentops.component"] == "api"
