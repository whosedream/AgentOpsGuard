from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agentops_guard.backend.telemetry import TelemetryMiddleware, _service_resource


def test_service_resource_ignores_ambient_otel_metadata(monkeypatch):
    private_marker = "private-ambient-resource-marker"
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", f"private.value={private_marker}")
    monkeypatch.setenv("OTEL_SERVICE_NAME", private_marker)

    resource = _service_resource("agentops-guard-api")

    assert dict(resource.attributes) == {"service.name": "agentops-guard-api"}
    assert private_marker not in json.dumps(dict(resource.attributes))


def test_http_spans_exclude_headers_query_and_body(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("telemetry-test")
    monkeypatch.setattr(trace, "get_tracer", lambda *_args, **_kwargs: tracer)
    app = FastAPI()
    app.add_middleware(TelemetryMiddleware, component="api")

    @app.post("/scan/{record_id}")
    def scan(record_id: str) -> dict[str, str]:
        return {"status": "ok"}

    secret = "secret-canary-never-enter-telemetry"
    with TestClient(app) as client:
        response = client.post(
            f"/scan/{secret}",
            params={"payload": secret},
            headers={"Authorization": f"Bearer {secret}"},
            json={"content": secret},
        )
        missing = client.get(f"/missing/{secret}")

    assert response.status_code == 200
    assert missing.status_code == 404
    spans = exporter.get_finished_spans()
    assert len(spans) == 2
    serialized = json.dumps(
        [{"name": span.name, "attributes": dict(span.attributes)} for span in spans]
    )
    assert secret not in serialized
    matched = next(span for span in spans if span.name == "POST /scan/{record_id}")
    unmatched = next(span for span in spans if span.name == "GET <unmatched>")
    assert matched.attributes["http.route"] == "/scan/{record_id}"
    assert "http.route" not in unmatched.attributes
    assert all("url.path" not in span.attributes for span in spans)
    assert all(span.attributes["agentops.component"] == "api" for span in spans)
