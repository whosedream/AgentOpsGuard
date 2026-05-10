from __future__ import annotations

import httpx

from agentops_guard.sdk.client import AgentOpsClient


def test_SPEC_P1_001_client_buffered_events_flush_and_retry():
    calls: list[list[dict[str, object]]] = []
    failures = {"remaining": 1}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/events":
            request.read().decode("utf-8")
            calls.append(httpx.Response(200).json() if False else [])
            if failures["remaining"] > 0:
                failures["remaining"] -= 1
                return httpx.Response(500)
            return httpx.Response(200, json=[])
        if request.url.path == "/v1/runs":
            return httpx.Response(200, json={"id": "run_client"})
        return httpx.Response(200, json={})

    client = AgentOpsClient(base_url="http://test", api_key="key", batch_size=2, flush_interval=60, max_retries=2)
    client._client = httpx.Client(transport=httpx.MockTransport(handler), headers={"X-AgentOps-Api-Key": "key"})

    client.record_events([{"event_type": "one"}], immediate=False)
    client.record_events([{"event_type": "two"}], immediate=False)
    client.flush()
    client.close()

    assert len(calls) >= 2
