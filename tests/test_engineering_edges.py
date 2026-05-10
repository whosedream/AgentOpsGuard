from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from agentops_guard.backend.database import Base
from agentops_guard.backend.services.api_keys import authenticate_api_key, create_api_key
from agentops_guard.gateway.transports.streamable_http import StreamableHttpTransport


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


def test_streamable_http_transport_success_paths():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tools/list"):
            return httpx.Response(200, json={"tools": [{"name": "http.echo"}]})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    transport = StreamableHttpTransport("http://mcp.test")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    original_get = httpx.get
    original_post = httpx.post
    try:
        httpx.get = client.get
        httpx.post = client.post
        assert transport.list_tools() == [{"name": "http.echo"}]
        assert transport.call_tool("http.echo", {})["content"][0]["text"] == "ok"
    finally:
        httpx.get = original_get
        httpx.post = original_post
        client.close()

