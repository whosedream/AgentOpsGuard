from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from agentops_guard.backend.database import Base
from agentops_guard.backend.services.api_keys import authenticate_api_key, create_api_key
from agentops_guard.gateway.transports import legacy_http
from agentops_guard.gateway.transports.legacy_http import LegacyHttpTransport


def test_api_key_expired_and_revoked_edges():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        expired, expired_token = create_api_key(
            session,
            "default",
            "expired",
            ["runs:read"],
            datetime.now(UTC) - timedelta(seconds=1),
        )
        active, active_token = create_api_key(session, "default", "active", ["runs:read"])
        active.revoked_at = datetime.now(UTC)
        session.commit()
        assert authenticate_api_key(session, expired_token) is None
        assert authenticate_api_key(session, active_token) is None
        assert expired.id.startswith("key_")


def test_legacy_http_transport_success_paths(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tools/list"):
            return httpx.Response(200, json={"tools": [{"name": "http.echo"}]})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    transport = LegacyHttpTransport("http://mcp.test")
    original_client = httpx.Client
    original_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        legacy_http.httpx,
        "Client",
        lambda **_kwargs: original_client(transport=httpx.MockTransport(handler)),
    )
    monkeypatch.setattr(
        legacy_http.httpx,
        "AsyncClient",
        lambda **_kwargs: original_async_client(transport=httpx.MockTransport(handler)),
    )

    assert transport.list_tools() == [{"name": "http.echo"}]
    assert transport.call_tool("http.echo", {})["content"][0]["text"] == "ok"
